/*
This module implements a similar API to what the crate `secrecy` provides.
So, why our own implementation?

First `secrecy::Secret<T>` does not put its contents in a `Box`.
Using `Box` is a general recommendation of working with secret data,
because it prevents the compiler from putting it on stack, thus avoiding possible copies on borrow.

Now, one could use `secrecy::Secret<Box<T>>`.
The problem here is that `secrecy::Secret` requires its type parameter to implement `Zeroize + Clone`.
This means that for a foreign type `F` (even if it does implement `Zeroize + Clone`)
we need to define `impl Zeroize + Clone for Box<F>`.
But the compiler does not allow impls of foreign traits on foreign types.
This means that we also need to wrap `F` in a local type, impl `Zeroize + Clone` for the wrapper,
and then for the box of the wrapper.
This is too much boilerplate.

Additionally, `secrecy::Secret<Box<T>>` means that after each `expose_secret()`
we will need to deal with opening the `Box` as well.
It's an inconvenience, albeit a minor one.

The situation may improve in the future, and `secrecy` will actually become usable.
*/

/// Adapted from: https://github.com/nucypher/rust-umbral/blob/master/umbral-pre/src/secret_box.rs
extern crate alloc;

use alloc::boxed::Box;
use std::fmt;

use zeroize::Zeroize;

/// A container for secret data.
/// Makes the usage of secret data explicit and easy to track,
/// prevents the secret data from being put on stack,
/// and zeroizes the contents on drop.
#[derive(Clone)]
pub struct SecretBox<T>(Box<T>)
where
    T: Zeroize + Clone;

impl<T: PartialEq + Zeroize + Clone> PartialEq<SecretBox<T>> for SecretBox<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T> SecretBox<T>
where
    T: Zeroize + Clone,
{
    pub fn new(val: T) -> Self {
        Self(Box::new(val))
    }

    /// Returns an immutable reference to the secret data.
    pub fn as_secret(&self) -> &T {
        self.0.as_ref()
    }

    /// Returns a mutable reference to the secret data.
    pub fn as_mut_secret(&mut self) -> &mut T {
        self.0.as_mut()
    }
}

impl<T> Drop for SecretBox<T>
where
    T: Zeroize + Clone,
{
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl<T> fmt::Debug for SecretBox<T>
where
    T: Zeroize + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBox<REDACTED>")
    }
}
