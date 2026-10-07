//! 带生存期与容量上限的通用 TTL 缓存
//!
//! # 设计原理
//! - **实现初衷**: 多个 DNS 服务商在解析 Zone / 域名 ID 时会发起远端请求，
//!   而同一轮同步中每个域名、每个协议都会重复解析同一 Zone，N+1 放大严重。
//!   引入本缓存以在「不新增 provider 字段」的前提下消除该放大。
//! - **核心优势**: 以 `(凭据身份, 查询键)` 为缓存键，天然隔离不同账号与
//!   不同目标；容量硬上限保证内存有界，TTL 保证配置变更后能自动收敛。
//! - **代价与局限**: 属进程内缓存，程序重启后需重新回源；TTL 窗口内的
//!   Zone 变更（服务商侧新建/删除）不会立即被感知。

use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// DNS Zone ID 缓存默认生存期（2 小时）
pub const DEFAULT_ZONE_CACHE_TTL: Duration = Duration::from_secs(7200);

/// DNS Zone ID 缓存默认容量上限
pub const DEFAULT_ZONE_CACHE_CAPACITY: usize = 128;

/// 跨提供商通用的 Zone ID 缓存复合键（按凭据摘要 + 根域名隔离）
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct ZoneCacheKey {
    pub auth_identity: String,
    pub root_domain: String,
}

impl ZoneCacheKey {
    /// 构造标准化的 Zone 缓存键（自动将根域名转为小写）
    pub fn new(auth_identity: impl Into<String>, root_domain: &str) -> Self {
        Self {
            auth_identity: auth_identity.into(),
            root_domain: root_domain.to_ascii_lowercase(),
        }
    }
}

/// 带 TTL 与容量上限的并发安全缓存池
pub struct TtlCache<K: Eq + Hash + Clone, V: Clone> {
    entries: RwLock<HashMap<K, (Instant, V)>>,
    ttl: Duration,
    capacity: usize,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlCache<K, V> {
    /// 创建缓存池
    ///
    /// # 参数
    /// - `ttl`: 条目生存期
    /// - `capacity`: 容量硬上限，达到后按插入顺序淘汰最旧条目
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(capacity)),
            ttl,
            capacity,
        }
    }

    /// 读取缓存值，未命中或已过期时返回 `None`
    ///
    /// # 设计原理
    /// 绝大多数查询均处于 TTL 有效期内：优先通过共享读锁并发读取，
    /// 仅当命中已过期条目时才升级获取独占写锁执行惰性淘汰，消除读多写少场景下的写锁争用。
    pub fn get(&self, key: &K) -> Option<V> {
        let now = Instant::now();
        let is_expired = {
            let guard = self.entries.read();
            match guard.get(key) {
                Some((created_at, value)) if now.duration_since(*created_at) < self.ttl => {
                    return Some(value.clone());
                }
                Some(_) => true,
                None => false,
            }
        };

        if is_expired {
            let mut guard = self.entries.write();
            if guard
                .get(key)
                .is_some_and(|(created_at, _)| now.duration_since(*created_at) >= self.ttl)
            {
                guard.remove(key);
            }
        }
        None
    }

    /// 写入缓存值
    ///
    /// 容量达到上限时淘汰「最久未更新」的一条，保证内存严格有界。
    /// 此处刻意不做全量 `retain`：写入路径应为 O(1)，全表扫描会成为热路径瓶颈。
    pub fn insert(&self, key: K, value: V) {
        let now = Instant::now();
        let mut guard = self.entries.write();

        if guard.len() >= self.capacity
            && !guard.contains_key(&key)
            && let Some(oldest) = guard
                .iter()
                .min_by_key(|(_, (created_at, _))| *created_at)
                .map(|(k, _)| k.clone())
        {
            guard.remove(&oldest);
        }

        guard.insert(key, (now, value));
    }

    /// 清空全部条目（供测试隔离使用）
    #[cfg(test)]
    pub fn clear(&self) {
        self.entries.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_cache_hit_and_miss() {
        let cache: TtlCache<String, u32> = TtlCache::new(Duration::from_secs(60), 10);
        assert_eq!(cache.get(&"missing".to_string()), None);

        cache.insert("a".to_string(), 1);
        assert_eq!(cache.get(&"a".to_string()), Some(1));
    }

    #[test]
    fn test_ttl_cache_expires_entries() {
        // TTL 为 0 时条目立即过期，验证过期判定生效
        let cache: TtlCache<String, u32> = TtlCache::new(Duration::from_secs(0), 10);
        cache.insert("a".to_string(), 1);
        assert_eq!(cache.get(&"a".to_string()), None, "TTL 过期后不得命中");
    }

    #[test]
    fn test_ttl_cache_capacity_is_bounded() {
        let cache: TtlCache<u32, u32> = TtlCache::new(Duration::from_secs(60), 4);
        for i in 0..20 {
            cache.insert(i, i);
        }
        assert!(
            cache.entries.read().len() <= 4,
            "缓存容量必须受硬上限约束，实际 {}",
            cache.entries.read().len()
        );
    }

    #[test]
    fn test_ttl_cache_preserves_recently_inserted_on_eviction() {
        let cache: TtlCache<u32, u32> = TtlCache::new(Duration::from_secs(60), 2);
        cache.insert(1, 1);
        cache.insert(2, 2);
        // 触发淘汰：应保留后插入的键
        cache.insert(3, 3);
        assert_eq!(cache.get(&3), Some(3));
    }

    #[test]
    fn test_ttl_cache_clear_resets_all_entries() {
        let cache: TtlCache<u32, u32> = TtlCache::new(Duration::from_secs(60), 8);
        cache.insert(1, 1);
        cache.insert(2, 2);
        cache.clear();
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), None);
    }
}
