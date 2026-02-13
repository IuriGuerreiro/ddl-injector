//! DLL proxy/hijacking injection method.
//!
//! This method generates a proxy DLL that forwards exports to the real system DLL
//! while loading a payload DLL. The proxy is deployed to the target application's
//! directory, where it will be loaded instead of the real system DLL.

use super::traits::{PreparationMethod, PreparationOptions, PreparationResult};
use super::proxy_generator::ProxyDllGenerator;
use crate::InjectionError;
use std::fs;
use std::path::Path;

/// DLL proxy/hijacking injector.
///
/// This injector generates a proxy DLL that:
/// 1. Loads the real system DLL from System32
/// 2. Forwards all exports to the real DLL
/// 3. Spawns a thread to load the embedded payload DLL
///
/// The proxy is deployed to the target application's directory,
/// where Windows' DLL search order will find it before System32.
pub struct DllProxyInjector;

impl DllProxyInjector {
    /// Create a new DLL proxy injector.
    pub fn new() -> Self {
        Self
    }

    /// Determine the target directory where the proxy should be deployed.
    ///
    /// Uses the provided target_directory option, or defaults to the
    /// directory containing the target executable.
    fn determine_target_directory(
        &self,
        target_exe_path: &Path,
        options: &PreparationOptions,
    ) -> Result<std::path::PathBuf, InjectionError> {
        if let Some(ref dir) = options.target_directory {
            if !dir.exists() {
                return Err(InjectionError::TargetDirectoryNotFound(
                    format!("Custom target directory does not exist: {}", dir.display())
                ));
            }
            Ok(dir.clone())
        } else {
            // Use directory containing the executable
            target_exe_path
                .parent()
                .map(|p| p.to_path_buf())
                .ok_or_else(|| InjectionError::TargetDirectoryNotFound(
                    format!("Cannot determine parent directory of: {}", target_exe_path.display())
                ))
        }
    }

    /// Backup an existing DLL if it exists in the target directory.
    fn backup_original_dll(
        &self,
        target_dir: &Path,
        dll_name: &str,
    ) -> Result<Option<std::path::PathBuf>, InjectionError> {
        let dll_path = target_dir.join(dll_name);

        if dll_path.exists() {
            log::info!("Backing up existing DLL: {}", dll_path.display());

            let backup_path = target_dir.join(format!("{}.backup", dll_name));

            fs::copy(&dll_path, &backup_path)
                .map_err(|e| InjectionError::Io(e))?;

            log::info!("Backed up to: {}", backup_path.display());
            Ok(Some(backup_path))
        } else {
            log::debug!("No existing DLL to backup at: {}", dll_path.display());
            Ok(None)
        }
    }
}

impl Default for DllProxyInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl PreparationMethod for DllProxyInjector {
    fn prepare(
        &self,
        target_exe_path: &Path,
        payload_dll_path: &Path,
        options: &PreparationOptions,
    ) -> Result<PreparationResult, InjectionError> {
        log::info!("Preparing DLL proxy injection");
        log::info!("  Target exe: {}", target_exe_path.display());
        log::info!("  Payload DLL: {}", payload_dll_path.display());
        log::info!("  System DLL: {}", options.system_dll_name);

        // Validate inputs
        if !target_exe_path.exists() {
            return Err(InjectionError::TargetDirectoryNotFound(
                format!("Target executable not found: {}", target_exe_path.display())
            ));
        }

        if !payload_dll_path.exists() {
            return Err(InjectionError::DllNotFound(
                format!("Payload DLL not found: {}", payload_dll_path.display())
            ));
        }

        // Determine target directory
        let target_dir = self.determine_target_directory(target_exe_path, options)?;
        log::info!("  Target directory: {}", target_dir.display());

        // Backup original DLL if requested
        let backup_path = if options.backup_original {
            self.backup_original_dll(&target_dir, &options.system_dll_name)?
        } else {
            None
        };

        // Generate proxy DLL
        log::info!("Generating proxy DLL...");
        let generator = ProxyDllGenerator::new(&options.system_dll_name, payload_dll_path)?;
        let compiled_proxy_path = generator.generate()?;

        // Deploy proxy to target directory
        let proxy_dest_path = target_dir.join(&options.system_dll_name);
        log::info!("Deploying proxy to: {}", proxy_dest_path.display());

        fs::copy(&compiled_proxy_path, &proxy_dest_path)
            .map_err(|e| InjectionError::PayloadEmbeddingFailed(
                format!("Failed to copy proxy DLL to target directory: {}", e)
            ))?;

        // Build user instructions
        let instructions = format!(
            r#"DLL Proxy Deployed Successfully
=================================

Proxy DLL: {}
System DLL: {}
Target Directory: {}
{}

To activate:
1. Launch the target application normally: {}
2. The proxy DLL will be loaded automatically by Windows
3. Your payload will execute in the application's context

The proxy DLL forwards all exports to the real system DLL,
so the application will function normally while your payload runs.

To remove:
- {}
"#,
            proxy_dest_path.display(),
            options.system_dll_name,
            target_dir.display(),
            if let Some(ref backup) = backup_path {
                format!("Backup created: {}", backup.display())
            } else {
                "No backup created (DLL did not exist)".to_string()
            },
            target_exe_path.display(),
            if backup_path.is_some() {
                format!("Run cleanup to restore from backup: injector-cli --method dll-proxy --cleanup {}", target_exe_path.display())
            } else {
                format!("Delete the proxy DLL: {}", proxy_dest_path.display())
            }
        );

        Ok(PreparationResult {
            proxy_dll_path: proxy_dest_path,
            backup_path,
            instructions,
        })
    }

    fn name(&self) -> &'static str {
        "DLL Proxy/Hijacking"
    }

    fn cleanup(&self, target_exe_path: &Path) -> Result<(), InjectionError> {
        log::info!("Cleaning up DLL proxy injection");

        let target_dir = target_exe_path
            .parent()
            .ok_or_else(|| InjectionError::TargetDirectoryNotFound(
                format!("Cannot determine parent directory of: {}", target_exe_path.display())
            ))?;

        // Look for .backup files in target directory
        let entries = fs::read_dir(target_dir)
            .map_err(|e| InjectionError::Io(e))?;

        let mut restored_count = 0;

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();

            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".backup") {
                    let original_name = name.trim_end_matches(".backup");
                    let original_path = target_dir.join(original_name);

                    log::info!("Restoring {} from backup", original_name);

                    // Remove proxy DLL
                    if original_path.exists() {
                        fs::remove_file(&original_path)
                            .map_err(|e| InjectionError::Io(e))?;
                    }

                    // Restore from backup
                    fs::copy(&path, &original_path)
                        .map_err(|e| InjectionError::Io(e))?;

                    // Delete backup
                    fs::remove_file(&path)
                        .map_err(|e| InjectionError::Io(e))?;

                    log::info!("Restored: {}", original_path.display());
                    restored_count += 1;
                }
            }
        }

        if restored_count == 0 {
            log::warn!("No backup files found in target directory");
        } else {
            log::info!("Restored {} DLL(s) from backup", restored_count);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_new_injector() {
        let injector = DllProxyInjector::new();
        assert_eq!(injector.name(), "DLL Proxy/Hijacking");
    }

    #[test]
    fn test_determine_target_directory_from_exe() {
        let injector = DllProxyInjector::new();

        let exe_path = PathBuf::from("C:\\test\\app\\game.exe");
        let options = PreparationOptions::new("version.dll".to_string());

        // This will fail because the path doesn't exist, but we can test the logic
        // by checking the error message
        let result = injector.determine_target_directory(&exe_path, &options);

        // Since the exe doesn't exist, parent() will work but the path won't exist
        // Actually, parent() works even if the path doesn't exist
        if let Ok(dir) = result {
            assert_eq!(dir, PathBuf::from("C:\\test\\app"));
        }
    }

    #[test]
    fn test_determine_target_directory_custom() {
        let injector = DllProxyInjector::new();

        let exe_path = PathBuf::from("C:\\test\\app\\game.exe");

        // Use temp directory as it exists
        let custom_dir = std::env::temp_dir();
        let options = PreparationOptions::new("version.dll".to_string())
            .with_target_directory(custom_dir.clone());

        let result = injector.determine_target_directory(&exe_path, &options);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), custom_dir);
    }

    #[test]
    fn test_backup_original_dll_not_exists() {
        let injector = DllProxyInjector::new();

        // Use temp directory
        let temp_dir = std::env::temp_dir().join(format!(
            "test_backup_not_exists_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        fs::create_dir_all(&temp_dir).unwrap();

        let result = injector.backup_original_dll(&temp_dir, "nonexistent.dll");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_backup_original_dll_exists() {
        let injector = DllProxyInjector::new();

        // Create temp directory and file
        let temp_dir = std::env::temp_dir().join(format!(
            "test_backup_exists_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        fs::create_dir_all(&temp_dir).unwrap();

        let test_dll_path = temp_dir.join("test.dll");
        fs::write(&test_dll_path, b"test data").unwrap();

        let result = injector.backup_original_dll(&temp_dir, "test.dll");
        assert!(result.is_ok());

        let backup = result.unwrap();
        assert!(backup.is_some());

        let backup_path = backup.unwrap();
        assert!(backup_path.exists());
        assert_eq!(backup_path.file_name().unwrap(), "test.dll.backup");

        // Verify backup contents
        let backup_data = fs::read(&backup_path).unwrap();
        assert_eq!(backup_data, b"test data");

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }
}
