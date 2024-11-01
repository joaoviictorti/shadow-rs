#[repr(C)]
pub enum KAPC_ENVIROMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
}

#[derive(Clone, Copy)]
pub enum COMUNICATION_TYPE {
    TCP = 3,
    UDP = 1
}