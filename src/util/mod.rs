use min_max_heap::MinMaxHeap;

pub struct FixedHeap<T> {
    inner: MinMaxHeap<T>,
    capacity: usize,
}

impl<T: Ord> FixedHeap<T> {
    pub fn new(capacity: usize) -> FixedHeap<T> {
        FixedHeap {
            inner: MinMaxHeap::with_capacity(capacity),
            capacity,
        }
    }

    pub fn insert(&mut self, v: T) -> Option<T> {
        if self.inner.len() == self.capacity {
            if v > *self.inner.peek_min().unwrap() {
                Some(self.inner.push_pop_min(v))
            } else {
                Some(v)
            }
        } else {
            self.inner.push(v);
            None
        }
    }

    pub fn into_inner(self) -> MinMaxHeap<T> {
        self.inner
    }
}
