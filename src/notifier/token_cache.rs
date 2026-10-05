use crate::notifier::trait_def::NotifyError;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, Instant};

/// 内存缓存的凭据实体
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// 基于双重检查锁 (Double-Checked Locking) 的通用 Token 缓存组件
///
/// # 设计原理
/// - **实现初衷**: 统一微信公众号与企业微信等多渠道的 AccessToken 缓存与刷新机制，
///   消除重复的手写 DCL 样板代码，杜绝瞬时并发通知击穿远端接口限流。
/// - **核心优势**: 锁前快速读，锁后二次确认；集成容量硬上限与过期项清理，防止内存泄露。
/// - **代价与局限**: 针对单机进程内复用，多实例部署需各自分别向远端换取 Token。
pub struct DclTokenCache {
    cache: RwLock<HashMap<String, CachedToken>>,
    mutex: tokio::sync::Mutex<()>,
    max_capacity: usize,
}

impl DclTokenCache {
    /// 创建指定容量上限的 Token 缓存池
    pub fn new(max_capacity: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            mutex: tokio::sync::Mutex::new(()),
            max_capacity,
        }
    }

    /// 获取 Token，若缓存缺失或过期则调用 `fetcher` 异步刷新
    pub async fn get_or_fetch<F, Fut>(&self, key: &str, fetcher: F) -> Result<String, NotifyError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(String, Duration), NotifyError>>,
    {
        // 1. 快速检查有效缓存
        {
            let guard = self.cache.read();
            if let Some(entry) = guard.get(key)
                && Instant::now() < entry.expires_at
            {
                return Ok(entry.token.clone());
            }
        }

        // 2. 获取异步互斥锁防止并发击穿远端 API
        let _guard = self.mutex.lock().await;

        // 3. 双重检查确认是否已被先序协程刷新完成
        {
            let guard = self.cache.read();
            if let Some(entry) = guard.get(key)
                && Instant::now() < entry.expires_at
            {
                return Ok(entry.token.clone());
            }
        }

        // 4. 执行远端异步拉取
        let (token, ttl) = fetcher().await?;
        let expires_at = Instant::now() + ttl;

        // 5. 写入写锁并进行容量保护淘汰
        let mut guard = self.cache.write();
        if guard.len() >= self.max_capacity {
            let now = Instant::now();
            guard.retain(|_, v| v.expires_at > now);
            if guard.len() >= self.max_capacity {
                guard.clear();
            }
        }
        guard.insert(
            key.to_string(),
            CachedToken {
                token: token.clone(),
                expires_at,
            },
        );

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_dcl_token_cache_reuse_and_expiration() {
        let cache = DclTokenCache::new(10);
        let fetch_count = Arc::new(AtomicUsize::new(0));

        // 首次获取触发拉取
        let count_clone = fetch_count.clone();
        let token = cache
            .get_or_fetch("app_1", || async {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(("token_abc".to_string(), Duration::from_secs(60)))
            })
            .await
            .unwrap();
        assert_eq!(token, "token_abc");
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

        // 缓存有效期内复用，不触发拉取
        let count_clone = fetch_count.clone();
        let token = cache
            .get_or_fetch("app_1", || async {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(("token_new".to_string(), Duration::from_secs(60)))
            })
            .await
            .unwrap();
        assert_eq!(token, "token_abc");
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_dcl_token_cache_capacity_eviction() {
        let cache = DclTokenCache::new(2);

        // 插入 2 个有效 key
        cache
            .get_or_fetch("k1", || async {
                Ok(("t1".to_string(), Duration::from_secs(60)))
            })
            .await
            .unwrap();
        cache
            .get_or_fetch("k2", || async {
                Ok(("t2".to_string(), Duration::from_secs(60)))
            })
            .await
            .unwrap();

        // 插入第 3 个 key 触发清理，由于 k1 和 k2 都未过期且已达上限，执行清理
        cache
            .get_or_fetch("k3", || async {
                Ok(("t3".to_string(), Duration::from_secs(60)))
            })
            .await
            .unwrap();

        let guard = cache.cache.read();
        assert!(guard.len() <= 2);
    }
}
