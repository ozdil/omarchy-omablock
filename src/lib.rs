pub mod ai;
pub mod kernel;
pub mod secure_fs;
pub mod self_defense;
pub mod subproc;

pub use ai::{AiClassification, AiRiskAssessment, DgaClassifier};
pub use kernel::{KernelFilterStatus, KernelNetfilter};
pub use self_defense::{calculate_self_exe_sha256, constant_time_eq, enforce_anti_tamper, SecureBuffer};

