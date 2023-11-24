#[cfg(feature = "askar_wallet")]
use aries_askar::entry::TagFilter;

pub enum SearchFilter {
    #[cfg(feature = "vdrtools_wallet")]
    JsonFilter(String),
    #[cfg(feature = "askar_wallet")]
    TagFilter(TagFilter),
}
