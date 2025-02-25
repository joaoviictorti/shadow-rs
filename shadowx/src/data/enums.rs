#[repr(C)]
pub enum KAPC_ENVIROMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment,
}

#[derive(Clone, Copy)]
pub enum COMUNICATION_TYPE {
    TCP = 3,
    UDP = 1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum KTHREAD_STATE {
	Initialized,
	Ready,
	Running,
	Standby,
	Terminated,
	Waiting,
	Transition,
	DeferredReady,
	GateWaitObsolete,
	WaitingForProcessInSwap,
	MaximumThreadState
}
