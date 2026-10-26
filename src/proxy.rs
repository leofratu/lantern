use crate::model::Result;
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, watch},
    time::{Instant, sleep_until, timeout},
};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileInput {
    pub name: String,
    pub down_kbps: u64,
    pub up_kbps: u64,
}

impl ProfileInput {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.chars().count() > 60 {
            return Err("Enter an app profile name of 1–60 characters".into());
        }
        if !(8..=1_000_000).contains(&self.down_kbps) || !(8..=1_000_000).contains(&self.up_kbps) {
            return Err("Each limit must be between 0.008 and 1,000 Mbps".into());
        }
        Ok(())
    }
}

struct Budget {
    kbps: AtomicU64,
    next: Mutex<Instant>,
}

impl Budget {
    fn new(kbps: u64) -> Self {
        Self {
            kbps: AtomicU64::new(kbps),
            next: Mutex::new(Instant::now()),
        }
    }
    async fn pace(&self, bytes: usize) {
        let deadline = {
            let mut next = self.next.lock().await;
            let duration = Duration::from_secs_f64(
                bytes as f64 * 8.0 / (self.kbps.load(Ordering::Relaxed) as f64 * 1000.0),
            );
            *next = (*next).max(Instant::now()) + duration;
            *next
        };
        sleep_until(deadline).await;
    }
    async fn update(&self, kbps: u64) {
        self.kbps.store(kbps, Ordering::Relaxed);
        *self.next.lock().await = Instant::now();
    }
}

pub struct Profile {
    pub id: Uuid,
    name: Mutex<String>,
    port: u16,
    down: Budget,
    up: Budget,
    downloaded: AtomicU64,
    uploaded: AtomicU64,
    active: AtomicUsize,
    failures: AtomicU64,
    stop: watch::Sender<bool>,
}

#[derive(Serialize)]
pub struct ProfileView {
    pub id: Uuid,
    pub name: String,
    pub port: u16,
    pub down_kbps: u64,
    pub up_kbps: u64,
    pub downloaded: u64,
    pub uploaded: u64,
    pub active: usize,
    pub failures: u64,
}

impl Profile {
    pub async fn start(input: ProfileInput, capacity: Arc<Semaphore>) -> Result<Arc<Self>> {
        input.validate()?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let (stop, mut stopped) = watch::channel(false);
        let profile = Arc::new(Self {
            id: Uuid::new_v4(),
            name: Mutex::new(input.name.trim().into()),
            port,
            down: Budget::new(input.down_kbps),
            up: Budget::new(input.up_kbps),
            downloaded: AtomicU64::new(0),
            uploaded: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            failures: AtomicU64::new(0),
            stop,
        });
        let owned = profile.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = stopped.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break; };
                        let Ok(permit) = capacity.clone().try_acquire_owned() else { owned.failures.fetch_add(1, Ordering::Relaxed); continue; };
                        let p = owned.clone();
                        let mut canceled = p.stop.subscribe();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if *canceled.borrow() { return; }
                            p.active.fetch_add(1, Ordering::Relaxed);
                            tokio::select! {
                                biased;
                                _ = canceled.changed() => {},
                                result = p.serve(socket) => { if result.is_err() { p.failures.fetch_add(1, Ordering::Relaxed); } }
                            }
                            p.active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                }
            }
        });
        Ok(profile)
    }

    pub async fn view(&self) -> ProfileView {
        ProfileView {
            id: self.id,
            name: self.name.lock().await.clone(),
            port: self.port,
            down_kbps: self.down.kbps.load(Ordering::Relaxed),
            up_kbps: self.up.kbps.load(Ordering::Relaxed),
            downloaded: self.downloaded.load(Ordering::Relaxed),
            uploaded: self.uploaded.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
        }
    }

    pub async fn update(&self, input: ProfileInput) -> Result<()> {
        input.validate()?;
        *self.name.lock().await = input.name.trim().into();
        self.down.update(input.down_kbps).await;
        self.up.update(input.up_kbps).await;
        Ok(())
    }

    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    async fn serve(&self, mut client: TcpStream) -> std::io::Result<()> {
        let remote = timeout(Duration::from_secs(10), handshake(&mut client)).await??;
        let (read_client, write_client) = client.into_split();
        let (read_remote, write_remote) = remote.into_split();
        tokio::try_join!(
            pipe(read_client, write_remote, &self.up, &self.uploaded),
            pipe(read_remote, write_client, &self.down, &self.downloaded)
        )?;
        Ok(())
    }
}

async fn handshake(client: &mut TcpStream) -> std::io::Result<TcpStream> {
    let invalid =
        || std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid SOCKS5 request");
    if client.read_u8().await? != 5 {
        return Err(invalid());
    }
    let count = client.read_u8().await?;
    let mut methods = vec![0; usize::from(count)];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        client.write_all(&[5, 255]).await?;
        return Err(invalid());
    }
    client.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    client.read_exact(&mut header).await?;
    if header[..3] != [5, 1, 0] {
        client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(invalid());
    }
    let host = match header[3] {
        1 => {
            let mut bytes = [0; 4];
            client.read_exact(&mut bytes).await?;
            std::net::Ipv4Addr::from(bytes).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            client.read_exact(&mut bytes).await?;
            std::net::Ipv6Addr::from(bytes).to_string()
        }
        3 => {
            let len = client.read_u8().await?;
            let mut bytes = vec![0; usize::from(len)];
            client.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| invalid())?
        }
        _ => return Err(invalid()),
    };
    let port = client.read_u16().await?;
    match timeout(
        Duration::from_secs(5),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(remote)) => {
            client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Ok(remote)
        }
        _ => {
            client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "Destination unavailable",
            ))
        }
    }
}

async fn pipe(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    budget: &Budget,
    counter: &AtomicU64,
) -> std::io::Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        // About 100 ms of data per read, bounded by a fixed 16 KiB allocation.
        let chunk =
            (budget.kbps.load(Ordering::Relaxed) as usize * 1000 / 8 / 10).clamp(128, buffer.len());
        let n = timeout(Duration::from_secs(300), reader.read(&mut buffer[..chunk])).await??;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        budget.pace(n).await;
        timeout(Duration::from_secs(30), writer.write_all(&buffer[..n])).await??;
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn proxy_relays_shapes_and_stops_existing_connections() {
        let echo = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo server");
        let target = echo.local_addr().expect("echo address").port();
        let echo_job = tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.expect("accept echo connection");
            let mut bytes = [0; 1000];
            s.read_exact(&mut bytes).await.expect("read echo payload");
            s.write_all(&bytes).await.expect("write echo payload");
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let p = Profile::start(
            ProfileInput {
                name: "test".into(),
                down_kbps: 80,
                up_kbps: 80,
            },
            Arc::new(Semaphore::new(2)),
        )
        .await
        .expect("start proxy profile");
        let mut client = TcpStream::connect(("127.0.0.1", p.port))
            .await
            .expect("connect proxy");
        client
            .write_all(&[5, 1, 0])
            .await
            .expect("send SOCKS greeting");
        let mut reply = [0; 2];
        client
            .read_exact(&mut reply)
            .await
            .expect("read SOCKS greeting");
        assert_eq!(reply, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&target.to_be_bytes());
        client
            .write_all(&request)
            .await
            .expect("send SOCKS CONNECT");
        let mut accepted = [0; 10];
        client
            .read_exact(&mut accepted)
            .await
            .expect("read SOCKS CONNECT reply");
        assert_eq!(accepted[1], 0);
        let start = Instant::now();
        client
            .write_all(&[42; 1000])
            .await
            .expect("send proxied payload");
        let mut data = [0; 1000];
        client
            .read_exact(&mut data)
            .await
            .expect("receive proxied payload");
        assert_eq!(data, [42; 1000]);
        assert!(start.elapsed() >= Duration::from_millis(190));
        assert_eq!(p.view().await.downloaded, 1000);
        p.stop();
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), client.read(&mut byte))
                .await
                .expect("stopping closes connection within a second")
                .expect("read connection close"),
            0
        );
        echo_job.abort();
    }

    #[tokio::test]
    async fn budget_is_shared_by_connections() {
        let budget = Arc::new(Budget::new(80));
        let start = Instant::now();
        let a = budget.clone();
        let b = budget.clone();
        tokio::join!(a.pace(1000), b.pace(1000));
        assert!(start.elapsed() >= Duration::from_millis(190));
    }
}
