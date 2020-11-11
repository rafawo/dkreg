// Copyright (c) 2020 Rafael Alcaraz Mercado. All rights reserved.
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
// THE SOURCE CODE IS AVAILABLE UNDER THE ABOVE CHOSEN LICENSE "AS IS", WITH NO WARRANTIES.

use winapi::shared::{
    bcrypt::{
        BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
        BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE,
        BCRYPT_SHA1_ALGORITHM, MS_PRIMITIVE_PROVIDER,
    },
    guiddef::GUID,
};

pub struct Type5Guid {
    algorithm: BCRYPT_ALG_HANDLE,
    hash: BCRYPT_HASH_HANDLE,
}

impl Drop for Type5Guid {
    fn drop(&mut self) {
        if self.hash != std::ptr::null_mut() {
            unsafe {
                BCryptDestroyHash(self.hash);
            }
        }
        if self.algorithm != std::ptr::null_mut() {
            unsafe {
                BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
        }
    }
}

impl Type5Guid {
    pub fn new() -> Type5Guid {
        let mut t = Type5Guid {
            algorithm: std::ptr::null_mut(),
            hash: std::ptr::null_mut(),
        };

        if 0 != unsafe {
            BCryptOpenAlgorithmProvider(
                &mut t.algorithm,
                widestring::WideCString::from_str(BCRYPT_SHA1_ALGORITHM)
                    .unwrap()
                    .as_ptr(),
                widestring::WideCString::from_str(MS_PRIMITIVE_PROVIDER)
                    .unwrap()
                    .as_ptr(),
                0,
            )
        } {
            panic!("Failed to open algorithm provider!");
        }

        if 0 != unsafe {
            BCryptCreateHash(
                t.algorithm,
                &mut t.hash,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                0,
            )
        } {
            panic!("Failed to create hash!");
        }

        t
    }

    pub fn create_guid(&self, seed: GUID, hash_data: &str) -> GUID {
        let mut network_order_namespace_guid = seed;

        // Convert the GUID from little endian to network byte order.
        network_order_namespace_guid.Data1 = u32::swap_bytes(seed.Data1);
        network_order_namespace_guid.Data2 = u16::swap_bytes(seed.Data2);
        network_order_namespace_guid.Data3 = u16::swap_bytes(seed.Data3);

        unsafe {
            // Hash the caller supplied namespace GUID.
            self.hash_data(std::slice::from_raw_parts_mut(
                &mut network_order_namespace_guid as *mut _ as *mut u8,
                std::mem::size_of::<GUID>(),
            ));

            // Hash the caller supplied data.
            let wcstr = widestring::WideCString::from_str(hash_data).unwrap();
            self.hash_data(std::slice::from_raw_parts_mut(
                wcstr.as_ptr() as *mut u8,
                wcstr.len() * std::mem::size_of::<winapi::shared::ntdef::WCHAR>(),
            ));
        }

        const SHA_1_OUTPUT_SIZE: usize = 20;
        let mut hash_output = [0 as u8; SHA_1_OUTPUT_SIZE];

        let mut guid = unsafe {
            // Compute the hash and receive it in the output buffer.
            if 0 != BCryptFinishHash(
                self.hash,
                hash_output.as_mut_ptr(),
                hash_output.len() as u32,
                0,
            ) {
                panic!("Failed to finish hash!");
            }
            *(hash_output.as_ptr() as *const GUID)
        };

        // Hash is in network byte order at this point.
        // Restore the byte order to little endian.
        guid.Data1 = u32::swap_bytes(guid.Data1);
        guid.Data2 = u16::swap_bytes(guid.Data2);
        guid.Data3 = u16::swap_bytes(guid.Data3);

        // Set version number to name-based SHA1 (5).
        guid.Data3 &= 0x0FFF;
        guid.Data3 |= 5 << 12;

        // Set variant field.
        guid.Data4[0] &= 0x3F;
        guid.Data4[0] |= 0x80;

        guid
    }

    unsafe fn hash_data(&self, b: &mut [u8]) {
        if 0 != BCryptHashData(self.hash, b.as_mut_ptr(), b.len() as u32, 0) {
            panic!("Failed to hash data!");
        }
    }
}

pub fn guid_to_string(guid: GUID) -> String {
    let uuid = uuid::Uuid::from_guid(guid).unwrap();
    let (d1, d2, d3, d4) = uuid.to_fields_le();
    uuid::Uuid::from_fields(d1, d2, d3, d4).unwrap().to_string()
}

pub fn layer_path_to_guid(path: &str) -> GUID {
    const CONTAINER_IMAGE_SEED: GUID = GUID {
        Data1: 0x800872c5,
        Data2: 0x909c,
        Data3: 0x403a,
        Data4: [0x89, 0xc9, 0x93, 0x1f, 0xe5, 0xe2, 0xfd, 0x08],
    };
    let hash_data = std::path::Path::new(path)
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    Type5Guid::new().create_guid(CONTAINER_IMAGE_SEED, &hash_data)
}
