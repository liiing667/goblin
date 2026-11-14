//! Optional strict structural analysis for PE32/PE32+ binaries.
//!
//! The regular [`PE::parse`](crate::pe::PE::parse) API is intentionally lenient: it extracts
//! sections, imports, certificates, etc. without judging whether the resulting layout is
//! structurally sound. This module provides an opt-in strict pass,
//! [`PE::analyze`](crate::pe::PE::analyze), which validates the structural integrity of an
//! already-parsed PE and reports every anomaly it finds.
//!
//! The checks are unified for 32-bit and 64-bit binaries and cover:
//!
//! * RVA validity (section virtual ranges, entry point, data directories vs. `SizeOfImage`)
//! * File ranges (section raw data vs. headers, file size, and each other)
//! * Alignment (`FileAlignment`, `SectionAlignment`, section pointers, certificate table)
//! * Integer overflow in RVA/offset arithmetic
//!
//! Anomalies are returned sorted (stably) by their path, e.g. `sections[2].pointer_to_raw_data`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::pe::PE;
use crate::pe::data_directories::DataDirectoryType;

/// The category of a structural [`Anomaly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    /// An RVA or virtual range is invalid (out of image, unmapped, or not file-backed).
    InvalidRva,
    /// A file offset range points outside the underlying bytes.
    OutOfFileBounds,
    /// Two file ranges that must be disjoint overlap.
    Overlap,
    /// A value violates its alignment requirement.
    Misaligned,
    /// An integer computation overflowed its target width.
    IntegerOverflow,
}

/// A single structural anomaly found by [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Stable, human-readable location of the offending value, e.g.
    /// `sections[2].pointer_to_raw_data` or `optional_header.address_of_entry_point`.
    pub path: String,
    /// The category of this anomaly.
    pub kind: AnomalyKind,
    /// A detailed description of the anomaly.
    pub message: String,
}

/// The result of a strict structural analysis, see [`analyze`].
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    anomalies: Vec<Anomaly>,
}

impl Analysis {
    /// Whether the analysis found no anomalies.
    pub fn is_ok(&self) -> bool {
        self.anomalies.is_empty()
    }

    /// The anomalies found, sorted stably by [`Anomaly::path`].
    pub fn anomalies(&self) -> &[Anomaly] {
        &self.anomalies
    }

    /// Consumes the analysis, returning the anomalies sorted stably by [`Anomaly::path`].
    pub fn into_anomalies(self) -> Vec<Anomaly> {
        self.anomalies
    }
}

struct Report {
    anomalies: Vec<Anomaly>,
}

impl Report {
    fn new() -> Self {
        Report {
            anomalies: Vec::new(),
        }
    }

    fn anomaly(&mut self, path: String, kind: AnomalyKind, message: String) {
        self.anomalies.push(Anomaly {
            path,
            kind,
            message,
        });
    }

    fn finish(mut self) -> Analysis {
        // `sort_by` is stable, so anomalies sharing a path keep their detection order.
        self.anomalies.sort_by(|a, b| a.path.cmp(&b.path));
        Analysis {
            anomalies: self.anomalies,
        }
    }
}

fn directory_type_name(dd: DataDirectoryType) -> &'static str {
    match dd {
        DataDirectoryType::ExportTable => "export_table",
        DataDirectoryType::ImportTable => "import_table",
        DataDirectoryType::ResourceTable => "resource_table",
        DataDirectoryType::ExceptionTable => "exception_table",
        DataDirectoryType::CertificateTable => "certificate_table",
        DataDirectoryType::BaseRelocationTable => "base_relocation_table",
        DataDirectoryType::DebugTable => "debug_table",
        DataDirectoryType::Architecture => "architecture",
        DataDirectoryType::GlobalPtr => "global_ptr",
        DataDirectoryType::TlsTable => "tls_table",
        DataDirectoryType::LoadConfigTable => "load_config_table",
        DataDirectoryType::BoundImportTable => "bound_import_table",
        DataDirectoryType::ImportAddressTable => "import_address_table",
        DataDirectoryType::DelayImportDescriptor => "delay_import_descriptor",
        DataDirectoryType::ClrRuntimeHeader => "clr_runtime_header",
    }
}

/// The size a section occupies in memory: `VirtualSize`, falling back to
/// `SizeOfRawData` when the former is zero.
fn effective_virtual_size(section: &crate::pe::section_table::SectionTable) -> u32 {
    if section.virtual_size == 0 {
        section.size_of_raw_data
    } else {
        section.virtual_size
    }
}

/// Performs a strict structural analysis of an already-parsed PE binary.
///
/// Returns an [`Analysis`] describing every structural anomaly found; the parse API is
/// unaffected and this pass never fails - problems are reported, not returned as errors.
pub fn analyze(pe: &PE) -> Analysis {
    let mut report = Report::new();
    let file_size = pe.bytes.len() as u64;

    let optional_header = match &pe.header.optional_header {
        Some(optional_header) => optional_header,
        // Without an optional header there is no image layout to validate.
        None => return report.finish(),
    };

    let windows_fields = &optional_header.windows_fields;
    let file_alignment = windows_fields.file_alignment;
    let section_alignment = windows_fields.section_alignment;
    let size_of_image = windows_fields.size_of_image;
    let size_of_headers = windows_fields.size_of_headers;

    // Alignment of the image layout parameters.
    let file_alignment_valid = file_alignment != 0 && file_alignment.is_power_of_two();
    if !file_alignment_valid {
        report.anomaly(
            String::from("optional_header.file_alignment"),
            AnomalyKind::Misaligned,
            format!("file alignment {file_alignment:#x} is not a non-zero power of two"),
        );
    }
    let section_alignment_valid = section_alignment != 0;
    if !section_alignment_valid {
        report.anomaly(
            String::from("optional_header.section_alignment"),
            AnomalyKind::Misaligned,
            String::from("section alignment is zero"),
        );
    }
    if file_alignment_valid && section_alignment_valid {
        // Per the PE specification: if SectionAlignment is less than the architecture's
        // page size, FileAlignment must match it; otherwise FileAlignment may not exceed it.
        let consistent = if section_alignment < 0x1000 {
            section_alignment == file_alignment
        } else {
            file_alignment <= section_alignment
        };
        if !consistent {
            report.anomaly(
                String::from("optional_header.section_alignment"),
                AnomalyKind::Misaligned,
                format!(
                    "section alignment {section_alignment:#x} is inconsistent with file alignment {file_alignment:#x}"
                ),
            );
        }
        if size_of_image % section_alignment != 0 {
            report.anomaly(
                String::from("optional_header.size_of_image"),
                AnomalyKind::Misaligned,
                format!(
                    "size of image {size_of_image:#x} is not a multiple of section alignment {section_alignment:#x}"
                ),
            );
        }
    }
    if file_alignment_valid && size_of_headers % file_alignment != 0 {
        report.anomaly(
            String::from("optional_header.size_of_headers"),
            AnomalyKind::Misaligned,
            format!(
                "size of headers {size_of_headers:#x} is not a multiple of file alignment {file_alignment:#x}"
            ),
        );
    }
    if u64::from(size_of_headers) > file_size {
        report.anomaly(
            String::from("optional_header.size_of_headers"),
            AnomalyKind::OutOfFileBounds,
            format!("size of headers {size_of_headers:#x} exceeds file size {file_size:#x}"),
        );
    }
    if windows_fields.image_base % 0x10000 != 0 {
        report.anomaly(
            String::from("optional_header.image_base"),
            AnomalyKind::Misaligned,
            format!(
                "image base {:#x} is not a multiple of 64K",
                windows_fields.image_base
            ),
        );
    }
    if windows_fields
        .image_base
        .checked_add(u64::from(size_of_image))
        .is_none()
    {
        report.anomaly(
            String::from("optional_header.image_base"),
            AnomalyKind::IntegerOverflow,
            format!(
                "image base {:#x} + size of image {size_of_image:#x} overflows 64 bits",
                windows_fields.image_base
            ),
        );
    }

    // Section checks: virtual ranges (RVA), raw file ranges, and alignment.
    let mut raw_ranges: Vec<(usize, u64, u64)> = Vec::new();
    for (index, section) in pe.sections.iter().enumerate() {
        let prefix = format!("sections[{index}]");
        let virtual_size = effective_virtual_size(section);

        let virtual_end = match section.virtual_address.checked_add(virtual_size) {
            Some(virtual_end) => virtual_end,
            None => {
                report.anomaly(
                    format!("{prefix}.virtual_address"),
                    AnomalyKind::IntegerOverflow,
                    format!(
                        "virtual address {:#x} + virtual size {virtual_size:#x} overflows 32 bits",
                        section.virtual_address
                    ),
                );
                u32::MAX
            }
        };
        if u64::from(virtual_end) > u64::from(size_of_image) {
            report.anomaly(
                format!("{prefix}.virtual_size"),
                AnomalyKind::InvalidRva,
                format!(
                    "virtual range {:#x}..{virtual_end:#x} exceeds size of image {size_of_image:#x}",
                    section.virtual_address
                ),
            );
        }
        if section_alignment_valid && section.virtual_address % section_alignment != 0 {
            report.anomaly(
                format!("{prefix}.virtual_address"),
                AnomalyKind::Misaligned,
                format!(
                    "virtual address {:#x} is not a multiple of section alignment {section_alignment:#x}",
                    section.virtual_address
                ),
            );
        }

        if section.size_of_raw_data != 0 {
            let raw_start = u64::from(section.pointer_to_raw_data);
            let raw_end = raw_start + u64::from(section.size_of_raw_data);
            if file_alignment_valid && section.pointer_to_raw_data % file_alignment != 0 {
                report.anomaly(
                    format!("{prefix}.pointer_to_raw_data"),
                    AnomalyKind::Misaligned,
                    format!(
                        "pointer to raw data {raw_start:#x} is not a multiple of file alignment {file_alignment:#x}"
                    ),
                );
            }
            if raw_start < u64::from(size_of_headers) {
                report.anomaly(
                    format!("{prefix}.pointer_to_raw_data"),
                    AnomalyKind::Overlap,
                    format!(
                        "raw range {raw_start:#x}..{raw_end:#x} overlaps the headers (size of headers {size_of_headers:#x})"
                    ),
                );
            }
            if raw_end > file_size {
                report.anomaly(
                    format!("{prefix}.size_of_raw_data"),
                    AnomalyKind::OutOfFileBounds,
                    format!(
                        "raw range {raw_start:#x}..{raw_end:#x} exceeds file size {file_size:#x}"
                    ),
                );
            }
            raw_ranges.push((index, raw_start, raw_end));
        }
    }

    // Section raw ranges must not overlap each other.
    raw_ranges.sort_by_key(|&(_, start, _)| start);
    for pair in raw_ranges.windows(2) {
        let (prev_index, prev_start, prev_end) = pair[0];
        let (index, start, end) = pair[1];
        if start < prev_end {
            report.anomaly(
                format!("sections[{index}].pointer_to_raw_data"),
                AnomalyKind::Overlap,
                format!(
                    "raw range {start:#x}..{end:#x} overlaps raw range {prev_start:#x}..{prev_end:#x} of sections[{prev_index}]"
                ),
            );
        }
    }

    // Entry point: must be inside the image and backed by file data.
    let entry = optional_header.standard_fields.address_of_entry_point;
    if entry != 0 {
        if u64::from(entry) >= u64::from(size_of_image) {
            report.anomaly(
                String::from("optional_header.address_of_entry_point"),
                AnomalyKind::InvalidRva,
                format!("entry point {entry:#x} is outside size of image {size_of_image:#x}"),
            );
        }
        match pe.sections.iter().find(|section| {
            let start = section.virtual_address;
            let end = start.saturating_add(effective_virtual_size(section));
            start <= entry && entry < end
        }) {
            Some(section) if section.size_of_raw_data == 0 => {
                report.anomaly(
                    String::from("optional_header.address_of_entry_point"),
                    AnomalyKind::InvalidRva,
                    format!(
                        "entry point {entry:#x} lies in a section with no file backing (size of raw data is zero)"
                    ),
                );
            }
            Some(_) => {}
            None => {
                report.anomaly(
                    String::from("optional_header.address_of_entry_point"),
                    AnomalyKind::InvalidRva,
                    format!("entry point {entry:#x} is not contained in any section"),
                );
            }
        }
    }

    // Data directories. The certificate table is a file offset; every other
    // directory is an RVA and must stay within the image.
    for (directory_type, directory) in optional_header.data_directories.dirs() {
        let path = format!("data_directories.{}", directory_type_name(directory_type));
        if directory_type == DataDirectoryType::CertificateTable {
            let start = u64::from(directory.virtual_address);
            let end = start + u64::from(directory.size);
            if start % 8 != 0 {
                report.anomaly(
                    path.clone(),
                    AnomalyKind::Misaligned,
                    format!("certificate table file offset {start:#x} is not 8-byte aligned"),
                );
            }
            if end > file_size {
                report.anomaly(
                    path.clone(),
                    AnomalyKind::OutOfFileBounds,
                    format!(
                        "certificate table range {start:#x}..{end:#x} exceeds file size {file_size:#x}"
                    ),
                );
            }
        } else {
            if directory.virtual_address == 0 {
                report.anomaly(
                    path.clone(),
                    AnomalyKind::InvalidRva,
                    format!(
                        "directory has zero RVA but non-zero size {:#x}",
                        directory.size
                    ),
                );
                continue;
            }
            match directory.virtual_address.checked_add(directory.size) {
                Some(end) => {
                    if u64::from(end) > u64::from(size_of_image) {
                        report.anomaly(
                            path.clone(),
                            AnomalyKind::InvalidRva,
                            format!(
                                "directory range {:#x}..{end:#x} exceeds size of image {size_of_image:#x}",
                                directory.virtual_address
                            ),
                        );
                    }
                }
                None => {
                    report.anomaly(
                        path.clone(),
                        AnomalyKind::IntegerOverflow,
                        format!(
                            "directory RVA {:#x} + size {:#x} overflows 32 bits",
                            directory.virtual_address, directory.size
                        ),
                    );
                }
            }
        }
    }

    report.finish()
}
