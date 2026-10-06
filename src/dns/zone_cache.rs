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
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// 带 TTL 与容量上限的并发安全缓存池
///
/// # 类型设计
/// 采用 `LazyLock` 内部条目表而非裸 `RwLock<HashMap>`，使缓存池本身可作为
/// `static` 声明（provider 无需额外持有缓存字段，保持可 `Clone` 语义，
/// 也无需在 `create_dns_provider` 的 25 个分支中逐一注入）。
pub struct TtlCache<K: Eq + Hash + Clone, V: Clone> {
    entries: LazyLock<RwLock<HashMap<K, (Instant, V)>>>,
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
            entries: LazyLock::new(|| RwLock::new(HashMap::new())),
            ttl,
            capacity,
        }
    }

    /// 读取缓存值，未命中或已过期时返回 `None`
    pub fn get(&self, key: &K) -> Option<V> {
        let now = Instant::now();
        let mut guard = self.entries.write();

        match guard.get(key) {
            Some((created_at, value)) if now.duration_since(*created_at) < self.ttl => {
                Some(value.clone())
            }
            // 惰性清理：命中过期条目时顺手移除，避免无效条目长期占用容量
            Some(_) => {
                guard.remove(key);
                None
            }
            None => None,
        }
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
