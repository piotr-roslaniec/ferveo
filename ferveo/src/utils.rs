pub fn is_sorted<I>(data: I) -> bool
where
    I: IntoIterator,
    I::Item: Ord,
{
    let mut data = data.into_iter();
    let mut prev = match data.next() {
        None => return true,
        Some(x) => x,
    };
    for x in data {
        if prev > x {
            return false;
        }
        prev = x;
    }
    true
}
