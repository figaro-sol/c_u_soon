// A #[program] field with generic type args should be a hard compile error.
// The macro must reject it rather than silently generating a broken wrapper path.

use bytemuck::{Pod, Zeroable};
use c_u_later::CuLater;
use c_u_soon::TypeHash;

#[derive(Pod, Zeroable, Copy, Clone, TypeHash, CuLater)]
#[repr(C)]
struct ConcreteInner {
    #[program]
    val: u32,
}

// Type alias with an unused type parameter so that `Pair<u32>` in a field
// satisfies all trait bounds (it's just ConcreteInner) while still having
// generic path args that the macro must reject.
#[allow(type_alias_bounds)]
type Pair<_T> = ConcreteInner;

#[derive(Pod, Zeroable, TypeHash, CuLater, Copy, Clone)]
#[repr(C)]
struct HasGenericField {
    #[program]
    inner: Pair<u32>,
}

fn main() {}
