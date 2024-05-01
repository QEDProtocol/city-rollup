// START: Metal Hardware Acceleration for Apple Silicon Devices
#[cfg(feature = "metal")]
mod metal;
#[cfg(feature = "metal")]
pub type PoseidonGoldilocksHWAConfig = metal::PoseidonGoldilocksHWAMetalConfig;
// END: Metal Hardware Acceleration for Apple Silicon Devices

// START: Fallback to CPU if no Hardware Acceleration is Avaialble
#[cfg(not(feature = "metal"))]
mod fallback;
#[cfg(not(feature = "metal"))]
pub type PoseidonGoldilocksHWAConfig = fallback::PoseidonGoldilocksHWAFallbackConfig;
// END: Fallback to CPU if no Hardware Acceleration is Avaialble
