use std::path::{Path, PathBuf};

use crate::error::SentinelError;

#[derive(Debug, Clone, PartialEq)]
pub struct SystemdService {
    pub name: String,
    pub unit_path: PathBuf,
    pub unit_type: String,
}

pub struct ServiceDiscoverer {
    discovery_paths: Vec<PathBuf>,
}

impl ServiceDiscoverer {
    #[must_use]
    pub fn new(discovery_paths: Vec<String>) -> Self {
        Self {
            discovery_paths: discovery_paths.into_iter().map(PathBuf::from).collect(),
        }
    }

    pub fn discover(&self) -> Result<Vec<SystemdService>, SentinelError> {
        let mut services = Vec::new();

        for path in &self.discovery_paths {
            if !path.is_dir() {
                continue;
            }

            match std::fs::read_dir(path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let file_path = entry.path();
                        if let Some(service) = Self::parse_service_file(&file_path) {
                            services.push(service);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to read discovery path '{}': {}", path.display(), e);
                }
            }
        }

        services.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(services)
    }

    fn parse_service_file(path: &Path) -> Option<SystemdService> {
        let extension = path.extension()?.to_str()?;

        if extension != "service" {
            return None;
        }

        let name = path.file_stem()?.to_str()?.to_string();

        let unit_type = if is_user_created_service(path) {
            "user-created".to_string()
        } else {
            "system".to_string()
        };

        Some(SystemdService {
            name,
            unit_path: path.to_path_buf(),
            unit_type,
        })
    }
}

fn is_user_created_service(path: &Path) -> bool {
    let parent = path.parent().and_then(|p| p.to_str()).unwrap_or("");

    matches!(
        parent,
        "/etc/systemd/system"
            | "/etc/systemd/user"
            | "/usr/local/lib/systemd/system"
            | "/usr/local/lib/systemd/user"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_discoverer_creation() {
        let discoverer = ServiceDiscoverer::new(vec![
            "/etc/systemd/system".to_string(),
            "/usr/lib/systemd/system".to_string(),
        ]);
        assert_eq!(discoverer.discovery_paths.len(), 2);
    }

    #[test]
    fn test_discover_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let discoverer =
            ServiceDiscoverer::new(vec![temp_dir.path().to_str().unwrap().to_string()]);

        let services = discoverer.discover().unwrap();
        assert!(services.is_empty());
    }

    #[test]
    fn test_discover_service_files() {
        let temp_dir = TempDir::new().unwrap();

        std::fs::write(temp_dir.path().join("my-app.service"), "[Unit]").unwrap();
        std::fs::write(temp_dir.path().join("my-python-app.service"), "[Unit]").unwrap();
        std::fs::write(temp_dir.path().join("not-a-service.txt"), "content").unwrap();

        let discoverer =
            ServiceDiscoverer::new(vec![temp_dir.path().to_str().unwrap().to_string()]);

        let services = discoverer.discover().unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, "my-app");
        assert_eq!(services[1].name, "my-python-app");
    }

    #[test]
    fn test_is_user_created_service_etc_systemd() {
        let path = Path::new("/etc/systemd/system/my-app.service");
        assert!(is_user_created_service(path));
    }

    #[test]
    fn test_is_user_created_service_usr_lib() {
        let path = Path::new("/usr/lib/systemd/system/nginx.service");
        assert!(!is_user_created_service(path));
    }

    #[test]
    fn test_is_user_created_service_usr_local() {
        let path = Path::new("/usr/local/lib/systemd/system/custom.service");
        assert!(is_user_created_service(path));
    }

    #[test]
    fn test_parse_non_service_file() {
        let path = Path::new("/etc/systemd/system/my-app.timer");
        assert!(ServiceDiscoverer::parse_service_file(path).is_none());
    }

    #[test]
    fn test_parse_service_file() {
        let path = Path::new("/etc/systemd/system/my-app.service");
        let service = ServiceDiscoverer::parse_service_file(path).unwrap();
        assert_eq!(service.name, "my-app");
        assert_eq!(service.unit_type, "user-created");
    }

    #[test]
    fn test_discover_handles_missing_directory() {
        let discoverer = ServiceDiscoverer::new(vec!["/nonexistent/path".to_string()]);
        let services = discoverer.discover().unwrap();
        assert!(services.is_empty());
    }

    #[test]
    fn test_services_are_sorted() {
        let temp_dir = TempDir::new().unwrap();

        std::fs::write(temp_dir.path().join("zebra.service"), "[Unit]").unwrap();
        std::fs::write(temp_dir.path().join("alpha.service"), "[Unit]").unwrap();
        std::fs::write(temp_dir.path().join("beta.service"), "[Unit]").unwrap();

        let discoverer =
            ServiceDiscoverer::new(vec![temp_dir.path().to_str().unwrap().to_string()]);

        let services = discoverer.discover().unwrap();
        assert_eq!(services[0].name, "alpha");
        assert_eq!(services[1].name, "beta");
        assert_eq!(services[2].name, "zebra");
    }
}
