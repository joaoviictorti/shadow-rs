use crate::enums::Callbacks;

/// Callback Information for Enumeration (Output)
///
/// This struct represents the information about a callback that is used in an enumeration process.
/// It includes details like the callback's memory address, name, and operations associated with it.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CallbackInfoOutput {
    /// The memory address where the callback is located.
    pub address: usize,
    
    /// The name of the callback, represented as a UTF-16 array of fixed length (256).
    /// This is useful for systems (like Windows) that use UTF-16 strings.
    pub name: [u16; 256],
    
    /// The index of the callback in the enumeration.
    pub index: u8,
    
    /// The memory address of the pre-operation function associated with this callback.
    pub pre_operation: usize,
    
    /// The memory address of the post-operation function associated with this callback.
    pub post_operation: usize,
}

/// Callback Information for Action (Input)
///
/// This struct is used to represent input data when performing an action on a callback.
/// It includes the callback's index and the specific callback action to be taken.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CallbackInfoInput {
    /// The index of the callback that will be targeted by the action.
    pub index: usize,
    
    /// The specific callback action, represented by the `Callbacks` enum.
    pub callback: Callbacks,
}