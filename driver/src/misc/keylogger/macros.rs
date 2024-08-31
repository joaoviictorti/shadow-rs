// Reference: https://github.com/mirror/reactos/blob/c6d2b35ffc91e09f50dfb214ea58237509329d6b/reactos/win32ss/user/ntuser/input.h#L91

#[macro_export]
macro_rules! get_ks_byte {
    ($vk:expr) => {
        ($vk as usize * 2 / 8)
    };
}

#[macro_export]
macro_rules! get_ks_down_bit {
    ($vk:expr) => {
        1 << (($vk % 4) * 2)
    };
}

#[macro_export]
macro_rules! is_key_down {
    ($ks:expr, $vk:expr) => {
        ($ks[get_ks_byte!($vk)] & get_ks_down_bit!($vk)) != 0
    };
}

#[macro_export]
macro_rules! set_key_down {
    ($ks:expr, $vk:expr, $down:expr) => {
        if $down {
            $ks[get_ks_byte!($vk)] |= get_ks_down_bit!($vk);
        } else {
            $ks[get_ks_byte!($vk)] &= !get_ks_down_bit!($vk);
        }
    };
}
