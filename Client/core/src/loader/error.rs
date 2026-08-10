// BOF Loader Error Types
//
// 提供结构化的错误类型，替代简单的 String 错误

use thiserror::Error;

/// BOF 加载器错误类型
#[derive(Debug, Error)]
pub enum BofError {
    /// 不支持的架构
    #[error("Unsupported architecture: 0x{0:04X} (expected x86 or x64)")]
    UnsupportedArchitecture(u16),

    /// 载荷格式错误
    #[error("invalid image format: {0}")]
    InvalidCoffFormat(String),

    /// 数据太小
    #[error("image data too small: {0} bytes (minimum {1} bytes required)")]
    FileTooSmall(usize, usize),

    /// 符号未找到
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),

    /// 符号解析失败
    #[error("Failed to resolve symbol '{symbol}': {reason}")]
    SymbolResolutionFailed { symbol: String, reason: String },

    /// 重定位失败
    #[error("Relocation failed at offset 0x{offset:X}: {reason}")]
    RelocationFailed { offset: u32, reason: String },

    /// 未知的重定位类型
    #[error("Unknown relocation type: {0} for architecture {1}")]
    UnknownRelocationType(u16, String),

    /// 内存分配失败
    #[error("Memory allocation failed: {0}")]
    MemoryAllocationFailed(String),

    /// 内存保护失败
    #[error("Memory protection failed: {0}")]
    MemoryProtectionFailed(String),

    /// Module Overloading 失败
    #[error("image map failed for '{dll}': {reason}")]
    ModuleOverloadingFailed { dll: String, reason: String },

    /// 段未找到
    #[error("section '{0}' not found in host image")]
    SectionNotFound(String),

    /// 入口点未找到
    #[error("entry point '{0}' not found in payload")]
    EntryPointNotFound(String),

    /// 执行失败
    #[error("payload execution failed: {0}")]
    ExecutionFailed(String),

    /// 系统调用失败
    #[error("Syscall failed: {syscall} returned 0x{status:X}")]
    SyscallFailed { syscall: String, status: i32 },

    /// 边界检查失败
    #[error("Bounds check failed: attempted to access offset {offset} in buffer of size {size}")]
    BoundsCheckFailed { offset: usize, size: usize },

    /// 架构不匹配
    #[error("architecture mismatch: cannot execute {bof_arch} payload in {process_arch} process")]
    ArchitectureMismatch {
        bof_arch: String,
        process_arch: String,
    },

    /// 内部 API 调用失败
    #[error("plugin api call failed: {api} - {reason}")]
    BeaconApiError { api: String, reason: String },

    /// 参数解析失败
    #[error("failed to parse payload arguments: {0}")]
    ArgumentParseError(String),
}

impl BofError {
    /// 创建符号解析失败错误
    pub fn symbol_resolution_failed(symbol: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::SymbolResolutionFailed {
            symbol: symbol.into(),
            reason: reason.into(),
        }
    }

    /// 创建重定位失败错误
    pub fn relocation_failed(offset: u32, reason: impl Into<String>) -> Self {
        Self::RelocationFailed {
            offset,
            reason: reason.into(),
        }
    }

    /// 创建 Module Overloading 失败错误
    pub fn module_overloading_failed(dll: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ModuleOverloadingFailed {
            dll: dll.into(),
            reason: reason.into(),
        }
    }

    /// 创建系统调用失败错误
    pub fn syscall_failed(syscall: impl Into<String>, status: i32) -> Self {
        Self::SyscallFailed {
            syscall: syscall.into(),
            status,
        }
    }

    /// 创建边界检查失败错误
    pub fn bounds_check_failed(offset: usize, size: usize) -> Self {
        Self::BoundsCheckFailed { offset, size }
    }

    /// 创建架构不匹配错误
    pub fn architecture_mismatch(
        bof_arch: impl Into<String>,
        process_arch: impl Into<String>,
    ) -> Self {
        Self::ArchitectureMismatch {
            bof_arch: bof_arch.into(),
            process_arch: process_arch.into(),
        }
    }

    /// 创建 Beacon API 错误
    pub fn beacon_api_error(api: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::BeaconApiError {
            api: api.into(),
            reason: reason.into(),
        }
    }
}

/// BOF 加载器结果类型
pub type BofResult<T> = Result<T, BofError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = BofError::UnsupportedArchitecture(0x1234);
        assert_eq!(
            err.to_string(),
            "Unsupported architecture: 0x1234 (expected x86 or x64)"
        );

        let err = BofError::symbol_resolution_failed("CreateFileW", "API not found");
        assert!(err.to_string().contains("CreateFileW"));
        assert!(err.to_string().contains("API not found"));
    }

    #[test]
    fn test_error_constructors() {
        let err = BofError::relocation_failed(0x1000, "Invalid target address");
        match err {
            BofError::RelocationFailed { offset, reason } => {
                assert_eq!(offset, 0x1000);
                assert_eq!(reason, "Invalid target address");
            }
            _ => panic!("Wrong error type"),
        }
    }
}
