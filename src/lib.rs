//! IFRExtractor-RS library.
//!
//! Combines Framework and UEFI HII parsing and IFR extraction into a reusable Rust library.

// Parser
#[macro_use]
extern crate nom;
extern crate pyo3;
pub mod framework_parser;
pub mod uefi_parser;

// Main
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Write;
use std::path::Path;
use std::str;
use nom::lib::std::fmt::UpperHex;


// Python
use pyo3::prelude::*;
use pyo3::Py;
use pyo3::PyResult;
use pyo3::wrap_pyfunction;
use pyo3::types::PyModule;


fn write_min_max<T: UpperHex>(
    buf: &mut Vec<u8>,
    arr: &[Option<T>; 3],
    size: u8,
) {
    if let [Some(min), Some(max), Some(step)] = arr {
        write!(
            buf,
            ", Size: {size}, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
            min, max, step
        )
        .unwrap();
    }
}



/// A parsed HII string-package.
#[pyclass(get_all)]
#[derive(Debug, Clone)]
pub struct StringPackage {
    /// Byte offset in the original blob.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
    /// RFC-5646 language tag (e.g. "en-US").
    pub language: String,
    /// Map from StringId → actual string.
    pub string_id_map: HashMap<u16, String>,
}

/// A parsed HII form-package.
#[pyclass(get_all)]
#[derive(Debug, Clone)]
pub struct FormPackage {
    /// Byte offset in the original blob.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
    /// Number of unique strings used.
    pub used_strings: usize,
    /// Minimum StringId referenced.
    pub min_string_id: u16,
    /// Maximum StringId referenced.
    pub max_string_id: u16,
}



/// Python binding for `find_framework_packages`.
#[pyfunction]
fn find_framework_packages_py(
    py: Python,
    data: &[u8],
) -> PyResult<(Vec<Py<StringPackage>>, Vec<Py<FormPackage>>)> {
    let (ss, fs) = framework_find_string_and_form_packages(data);
    let ss_py = ss.into_iter().map(|s| Py::new(py, s).unwrap()).collect();
    let fs_py = fs.into_iter().map(|f| Py::new(py, f).unwrap()).collect();
    Ok((ss_py, fs_py))
}

/// Python binding for `extract_framework_ifr`.
#[pyfunction]
fn extract_framework_ifr_py(
    data: &[u8],
    form: PyRef<FormPackage>,
    string: PyRef<StringPackage>,
    verbose: bool,
) -> PyResult<String> {
    Ok(framework_ifr_extract_to_string(data, &*form, &*string, verbose))
}

/// Python binding for `find_uefi_packages`.
#[pyfunction]
fn find_uefi_packages_py(
    py: Python,
    data: &[u8],
) -> PyResult<(Vec<Py<StringPackage>>, Vec<Py<FormPackage>>)> {
    let (ss, fs) = uefi_find_string_and_form_packages(data);
    let ss_py = ss.into_iter().map(|s| Py::new(py, s).unwrap()).collect();
    let fs_py = fs.into_iter().map(|f| Py::new(py, f).unwrap()).collect();
    Ok((ss_py, fs_py))
}

/// Python binding for `extract_uefi_ifr`.
#[pyfunction]
fn extract_uefi_ifr_py(
    data: &[u8],
    form: PyRef<FormPackage>,
    string: PyRef<StringPackage>,
    verbose: bool,
) -> PyResult<String> {
    Ok(uefi_ifr_extract_to_string(data, &*form, &*string, verbose))
}


/// Scan `data` for all Framework HII string- and form-packages.
/// Returns `(string_packages, form_packages)`.
pub fn find_framework_packages(
    data: &[u8],
) -> (Vec<StringPackage>, Vec<FormPackage>) {
    framework_find_string_and_form_packages(data)
}

/// Extract the IFR text for one Framework HII form.
/// If `verbose` is `true`, prepends each opcode with its byte-offset.
pub fn extract_framework_ifr(
    data: &[u8],
    form_pkg: &FormPackage,
    string_pkg: &StringPackage,
    verbose: bool,
) -> String {
    framework_ifr_extract_to_string(data, form_pkg, string_pkg, verbose)
}

/// Scan `data` for all UEFI HII string- and form-packages.
/// Returns `(string_packages, form_packages)`.
pub fn find_uefi_packages(
    data: &[u8],
) -> (Vec<StringPackage>, Vec<FormPackage>) {
    uefi_find_string_and_form_packages(data)
}

/// Extract the IFR text for one UEFI HII form.
/// If `verbose` is `true`, prepends each opcode with its byte-offset.
pub fn extract_uefi_ifr(
    data: &[u8],
    form_pkg: &FormPackage,
    string_pkg: &StringPackage,
    verbose: bool,
) -> String {
    uefi_ifr_extract_to_string(data, form_pkg, string_pkg, verbose)
}

// -----------------------------------------------------------------------------
// Internal implementations (moved from `main.rs`; no file I/O here)
// -----------------------------------------------------------------------------

fn framework_find_string_and_form_packages(
    data: &[u8],
) -> (Vec<StringPackage>, Vec<FormPackage>) {
    let mut string_packages = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = framework_parser::hii_string_package_candidate(&data[i..]) {
            if let Ok((_, pkg)) = framework_parser::hii_package(candidate) {
                if let Some(payload) = pkg.Data {
                    if let Ok((_, spkg)) = framework_parser::hii_string_package(payload) {
                        // Determine language string
                        let lang_index = spkg.StringPointers
                            .iter()
                            .position(|&off| off == spkg.LanguageNameStringOffset)
                            .unwrap_or(0);
                        let language = spkg.Strings.get(lang_index).cloned().unwrap_or_default();
                        // Build ID→string map
                        let string_id_map = spkg.Strings
                            .iter()
                            .cloned()
                            .enumerate()
                            .map(|(idx, s)| (idx as u16, s))
                            .collect::<HashMap<_, _>>();
                        string_packages.push(StringPackage {
                            offset: i,
                            length: candidate.len(),
                            language,
                            string_id_map,
                        });
                        i += candidate.len();
                        continue;
                    }
                }
            }
        }
        i += 1;
    }

    if string_packages.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut form_packages = Vec::new();
    i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = framework_parser::hii_form_package_candidate(&data[i..]) {
            if let Ok((_, pkg)) = framework_parser::hii_package(candidate) {
                if let Some(payload) = pkg.Data {
                    if let Ok((_, ops)) = framework_parser::ifr_operations(payload) {
                        let mut ids = Vec::new();
                        use framework_parser::IfrOpcode::*;
                        for op in &ops {
                            if let Some(d) = op.Data {
                                match op.OpCode {
                                    Form => if let Ok((_, f)) = framework_parser::ifr_form(d) {
                                        ids.push(f.TitleStringId);
                                    },
                                    Subtitle => if let Ok((_, s)) = framework_parser::ifr_subtitle(d) {
                                        ids.push(s.SubtitleStringId);
                                    },
                                    Text => if let Ok((_, t)) = framework_parser::ifr_text(d) {
                                        ids.extend(&[t.HelpStringId, t.TextStringId, t.TextTwoStringId]);
                                    },
                                    OneOf => if let Ok((_, o)) = framework_parser::ifr_one_of(d) {
                                        ids.extend(&[o.PromptStringId, o.HelpStringId]);
                                    },
                                    CheckBox => if let Ok((_, c)) = framework_parser::ifr_check_box(d) {
                                        ids.extend(&[c.PromptStringId, c.HelpStringId]);
                                    },
                                    Numeric => if let Ok((_, n)) = framework_parser::ifr_numeric(d) {
                                        ids.extend(&[n.PromptStringId, n.HelpStringId]);
                                    },
                                    Password => if let Ok((_, p)) = framework_parser::ifr_password(d) {
                                        ids.extend(&[p.PromptStringId, p.HelpStringId]);
                                    },
                                    OneOfOption => if let Ok((_, o)) = framework_parser::ifr_one_of_option(d) {
                                        ids.push(o.OptionStringId);
                                    },
                                    FormSet => if let Ok((_, fs)) = framework_parser::ifr_form_set(d) {
                                        ids.extend(&[fs.TitleStringId, fs.HelpStringId]);
                                    },
                                    Ref => if let Ok((_, r)) = framework_parser::ifr_ref(d) {
                                        ids.extend(&[r.PromptStringId, r.HelpStringId]);
                                    },
                                    InconsistentIf => if let Ok((_, inc)) = framework_parser::ifr_inconsistent_if(d) {
                                        ids.push(inc.PopupStringId);
                                    },
                                    Date => if let Ok((_, dt)) = framework_parser::ifr_date(d) {
                                        ids.extend(&[dt.PromptStringId, dt.HelpStringId]);
                                    },
                                    Time => if let Ok((_, ti)) = framework_parser::ifr_time(d) {
                                        ids.extend(&[ti.PromptStringId, ti.HelpStringId]);
                                    },
                                    String => if let Ok((_, st)) = framework_parser::ifr_string(d) {
                                        ids.extend(&[st.PromptStringId, st.HelpStringId]);
                                    },
                                    SaveDefaults => if let Ok((_, sd)) = framework_parser::ifr_save_defaults(d) {
                                        ids.extend(&[sd.PromptStringId, sd.HelpStringId]);
                                    },
                                    RestoreDefaults => if let Ok((_, rd)) = framework_parser::ifr_restore_defaults(d) {
                                        ids.extend(&[rd.PromptStringId, rd.HelpStringId]);
                                    },
                                    Banner => if let Ok((_, b)) = framework_parser::ifr_banner(d) {
                                        ids.push(b.TitleStringId);
                                    },
                                    Inventory => if let Ok((_, inv)) = framework_parser::ifr_inventory(d) {
                                        ids.extend(&[inv.HelpStringId, inv.TextStringId, inv.TextTwoStringId]);
                                    },
                                    OrderedList => if let Ok((_, ol)) = framework_parser::ifr_ordered_list(d) {
                                        ids.extend(&[ol.PromptStringId, ol.HelpStringId]);
                                    },
                                    _ => {},
                                }
                            }
                        }
                        ids.sort_unstable();
                        ids.dedup();
                        if !ids.is_empty() {
                            form_packages.push(FormPackage {
                                offset: i,
                                length: candidate.len(),
                                used_strings: ids.len(),
                                min_string_id: *ids.first().unwrap(),
                                max_string_id: *ids.last().unwrap(),
                            });
                        }
                        i += candidate.len();
                        continue;
                    }
                }
            }
        }
        i += 1;
    }

    if form_packages.is_empty() {
        return (Vec::new(), Vec::new());
    }

    (string_packages, form_packages)
}

fn framework_ifr_extract_to_string(
    data: &[u8],
    form_pkg: &FormPackage,
    string_pkg: &StringPackage,
    verbose: bool,
) -> String {
    let mut text: Vec<u8> = Vec::new();
    let strings_map = &string_pkg.string_id_map;

    // Version and mode
    writeln!(
        &mut text,
        "Program version: {}, Extraction mode: Framework",
        env!("CARGO_PKG_VERSION")
    )
    .unwrap();

    // Locate the form package
    if let Ok((_, candidate)) = framework_parser::hii_form_package_candidate(&data[form_pkg.offset..]) {
        if let Ok((_, package)) = framework_parser::hii_package(candidate) {
            if let Ok((_, operations)) = framework_parser::ifr_operations(package.Data.unwrap()) {
                let mut scope_depth = 0usize;
                let mut offset = form_pkg.offset + 6;
                use framework_parser::IfrOpcode::*;
                for op in &operations {
                    // Decrease scope on end ops
                    if matches!(op.OpCode, EndFormSet | EndForm) {
                        scope_depth = scope_depth.saturating_sub(1);
                    }
                    if verbose {
                        write!(&mut text, "0x{:X}: ", offset).unwrap();
                    }
                    write!(
                        &mut text,
                        "{:width$}{:?} ",
                        "",            // first positional: the empty-string indent
                        op.OpCode,     // second positional: the opcode
                        width = scope_depth,  // named parameter for the dynamic width
                    ).unwrap();

                    if let Some(d) = op.Data {
                        match op.OpCode {
                            Form => if let Ok((_, f)) = framework_parser::ifr_form(d) {
                                write!(
                                    &mut text,
                                    "Title: \"{}\", FormId: 0x{:X}",
                                    strings_map.get(&f.TitleStringId).unwrap_or(&"InvalidId".into()),
                                    f.FormId
                                ).unwrap();
                                scope_depth += 1;
                            },
                            Subtitle => if let Ok((_, s)) = framework_parser::ifr_subtitle(d) {
                                write!(
                                    &mut text,
                                    "Subtitle: \"{}\"",
                                    strings_map.get(&s.SubtitleStringId).unwrap_or(&"InvalidId".into())
                                ).unwrap();
                            },
                            Text => if let Ok((_, t)) = framework_parser::ifr_text(d) {
                                write!(
                                    &mut text,
                                    "Text: \"{}\", TextTwo: \"{}\", Help: \"{}\", Flags: 0x{:X}, Key: 0x{:X}",
                                    strings_map.get(&t.TextStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&t.TextTwoStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&t.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    t.Flags,
                                    t.Key
                                ).unwrap();
                            },
                            Graphic => {},
                            OneOf => if let Ok((_, o)) = framework_parser::ifr_one_of(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}",
                                    strings_map.get(&o.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&o.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    o.QuestionId,
                                    o.Width
                                ).unwrap();
                            },
                            CheckBox => if let Ok((_, c)) = framework_parser::ifr_check_box(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                    strings_map.get(&c.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&c.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    c.QuestionId,
                                    c.Width,
                                    c.Flags,
                                    c.Key
                                ).unwrap();
                            },
                            Numeric => if let Ok((_, n)) = framework_parser::ifr_numeric(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}, Default: 0x{:X}",
                                    strings_map.get(&n.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&n.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    n.QuestionId,
                                    n.Width,
                                    n.Flags,
                                    n.Key,
                                    n.Min,
                                    n.Max,
                                    n.Step,
                                    n.Default
                                ).unwrap();
                            },
                            Password => if let Ok((_, p)) = framework_parser::ifr_password(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, MinSize: 0x{:X}, MaxSize: 0x{:X}, Encoding: 0x{:X}",
                                    strings_map.get(&p.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&p.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    p.QuestionId,
                                    p.Width,
                                    p.Flags,
                                    p.Key,
                                    p.MinSize,
                                    p.MaxSize,
                                    p.Encoding
                                ).unwrap();
                            },
                            OneOfOption => if let Ok((_, oo)) = framework_parser::ifr_one_of_option(d) {
                                write!(
                                    &mut text,
                                    "Option: \"{}\", Value: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                    strings_map.get(&oo.OptionStringId).unwrap_or(&"InvalidId".into()),
                                    oo.Value,
                                    oo.Flags,
                                    oo.Key
                                ).unwrap();
                            },
                            SuppressIf => if let Ok((_, si)) = framework_parser::ifr_supress_if(d) {
                                write!(&mut text, "Flags: 0x{:X}", si.Flags).unwrap();
                            },
                            EndForm => {},
                            Hidden => if let Ok((_, h)) = framework_parser::ifr_hidden(d) {
                                write!(
                                    &mut text,
                                    "Value: 0x{:X}, Key: 0x{:X}",
                                    h.Value,
                                    h.Key
                                ).unwrap();
                            },
                            EndFormSet => {},
                            FormSet => if let Ok((_, fs)) = framework_parser::ifr_form_set(d) {
                                write!(
                                    &mut text,
                                    "Title: \"{}\", Help: \"{}\", Guid: {}, Callback: 0x{:X}, Class: 0x{:X}, SubClass: 0x{:X}, NvDataSize: 0x{:X}",
                                    strings_map.get(&fs.TitleStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&fs.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    fs.Guid,
                                    fs.CallbackHandle,
                                    fs.Class,
                                    fs.SubClass,
                                    fs.NvDataSize
                                ).unwrap();
                                scope_depth += 1;
                            },
                            Ref => if let Ok((_, r)) = framework_parser::ifr_ref(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", FormId: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                    strings_map.get(&r.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&r.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    r.FormId,
                                    r.Flags,
                                    r.Key
                                ).unwrap();
                            },
                            End => {},
                            InconsistentIf => if let Ok((_, inc)) = framework_parser::ifr_inconsistent_if(d) {
                                write!(
                                    &mut text,
                                    "Popup: \"{}\", Flags: 0x{:X}",
                                    strings_map.get(&inc.PopupStringId).unwrap_or(&"InvalidId".into()),
                                    inc.Flags
                                ).unwrap();
                            },
                            EqIdVal => if let Ok((_, ev)) = framework_parser::ifr_eq_id_val(d) {
                                write!(&mut text, "QuestionId: 0x{:X}, Value: 0x{:X}", ev.QuestionId, ev.Value).unwrap();
                            },
                            EqIdId => if let Ok((_, eid)) = framework_parser::ifr_eq_id_id(d) {
                                write!(&mut text, "Question1: 0x{:X}, Question2: 0x{:X}", eid.QuestionId1, eid.QuestionId2).unwrap();
                            },
                            EqIdList => if let Ok((_, el)) = framework_parser::ifr_eq_id_list(d) {
                                write!(&mut text, "QuestionId: 0x{:X}, Width: 0x{:X}, List: {{", el.QuestionId, el.Width).unwrap();
                                for item in &el.List { write!(&mut text, " 0x{:X},", item).unwrap(); }
                                write!(&mut text, " }}").unwrap();
                            },
                            And | Or | Not | EndIf => {},
                            GrayOutIf => if let Ok((_, go)) = framework_parser::ifr_grayout_if(d) {
                                write!(&mut text, "Flags: 0x{:X}", go.Flags).unwrap();
                            },
                            Date => if let Ok((_, dt)) = framework_parser::ifr_date(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}, Default: 0x{:X}",
                                    strings_map.get(&dt.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&dt.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    dt.QuestionId,
                                    dt.Width,
                                    dt.Flags,
                                    dt.Key,
                                    dt.Min,
                                    dt.Max,
                                    dt.Step,
                                    dt.Default
                                ).unwrap();
                            },
                            Time => if let Ok((_, tm)) = framework_parser::ifr_time(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}, Default: 0x{:X}",
                                    strings_map.get(&tm.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&tm.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    tm.QuestionId,
                                    tm.Width,
                                    tm.Flags,
                                    tm.Key,
                                    tm.Min,
                                    tm.Max,
                                    tm.Step,
                                    tm.Default
                                ).unwrap();
                            },
                            String => if let Ok((_, st)) = framework_parser::ifr_string(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, MinSize: 0x{:X}, MaxSize: 0x{:X}",
                                    strings_map.get(&st.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&st.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    st.QuestionId,
                                    st.Width,
                                    st.Flags,
                                    st.Key,
                                    st.MinSize,
                                    st.MaxSize
                                ).unwrap();
                            },
                            Label => if let Ok((_, lb)) = framework_parser::ifr_label(d) {
                                write!(&mut text, "LabelId: 0x{:X}", lb.LabelId).unwrap();
                            },
                            SaveDefaults => if let Ok((_, sd)) = framework_parser::ifr_save_defaults(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", FormId: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                    strings_map.get(&sd.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&sd.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    sd.FormId,
                                    sd.Flags,
                                    sd.Key
                                ).unwrap();
                            },
                            RestoreDefaults => if let Ok((_, rd)) = framework_parser::ifr_restore_defaults(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", FormId: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                    strings_map.get(&rd.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&rd.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    rd.FormId,
                                    rd.Flags,
                                    rd.Key
                                ).unwrap();
                            },
                            Banner => if let Ok((_, bn)) = framework_parser::ifr_banner(d) {
                                write!(
                                    &mut text,
                                    "Title: \"{}\", LineNumber: 0x{:X}, Alignment: 0x{:X}",
                                    strings_map.get(&bn.TitleStringId).unwrap_or(&"InvalidId".into()),
                                    bn.LineNumber,
                                    bn.Alignment
                                ).unwrap();
                            },
                            Inventory => if let Ok((_, inv)) = framework_parser::ifr_inventory(d) {
                                write!(
                                    &mut text,
                                    "Text: \"{}\", TextTwo: \"{}\", Help: \"{}\"",
                                    strings_map.get(&inv.TextStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&inv.TextTwoStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&inv.HelpStringId).unwrap_or(&"InvalidId".into())
                                ).unwrap();
                            },
                            EqVarVal => if let Ok((_, evv)) = framework_parser::ifr_eq_var_val(d) {
                                write!(&mut text, "VariableId: 0x{:X}, Value: 0x{:X}", evv.VariableId, evv.Value).unwrap();
                            },
                            OrderedList => if let Ok((_, ol)) = framework_parser::ifr_ordered_list(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, MaxEntries: 0x{:X}",
                                    strings_map.get(&ol.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&ol.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    ol.QuestionId,
                                    ol.MaxEntries
                                ).unwrap();
                            },
                            VarStore => if let Ok((_, vs)) = framework_parser::ifr_var_store(d) {
                                write!(
                                    &mut text,
                                    "VarstoreId: 0x{:X}, Guid: {}, Name: \"{}\", Size: 0x{:X}",
                                    vs.VarStoreId,
                                    vs.Guid,
                                    vs.Name,
                                    vs.Size
                                ).unwrap();
                            },
                            VarStoreSelect => if let Ok((_, vss)) = framework_parser::ifr_var_store_select(d) {
                                write!(&mut text, "VarstoreId: 0x{:X}", vss.VarStoreId).unwrap();
                            },
                            VarStoreSelectPair => if let Ok((_, vsp)) = framework_parser::ifr_var_store_select_pair(d) {
                                write!(
                                    &mut text,
                                    "VarstoreId: 0x{:X}, SecondaryVarStoreId: 0x{:X}",
                                    vsp.VarStoreId,
                                    vsp.SecondaryVarStoreId
                                ).unwrap();
                            },
                            True | False | Greater | GreaterEqual | OemDefined | Oem | NvAccessCommand => {},
                            Unknown(x) => {
                                write!(&mut text, "RawData: {:02X?}", d).unwrap();
                                println!("Unknown opcode 0x{:X}", x);
                            }
                        }
                    }
                    offset += op.Length as usize;
                    writeln!(&mut text).unwrap();
                }
            }
        }
    }
    String::from_utf8(text).unwrap_or_default()
}



fn uefi_find_string_and_form_packages(data: &[u8]) -> (Vec<StringPackage>, Vec<FormPackage>) {
    let mut strings = Vec::new(); // String-to-id maps for all found string packages

    // Search for all string packages in the input file
    let mut i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = uefi_parser::hii_string_package_candidate(&data[i..]) {
            if let Ok((_, package)) = uefi_parser::hii_package(candidate) {
                if let Ok((_, string_package)) =
                    uefi_parser::hii_string_package(package.Data.unwrap())
                {
                    let mut string_id_map = HashMap::new(); // Map of StringIds to strings

                    // Parse SIBT blocks
                    if let Ok((_, sibt_blocks)) = uefi_parser::hii_sibt_blocks(string_package.Data)
                    {
                        string_id_map.insert(0_u16, String::new());
                        let mut current_string_index = 1;
                        for block in &sibt_blocks {
                            match block.Type {
                                // 0x00: End
                                uefi_parser::HiiSibtType::End => {}
                                // 0x10: StringScsu
                                uefi_parser::HiiSibtType::StringScsu => {
                                    if let Ok((_, string)) =
                                        uefi_parser::sibt_string_scsu(block.Data.unwrap())
                                    {
                                        string_id_map.insert(current_string_index, string);
                                        current_string_index += 1;
                                    }
                                }
                                // 0x11: StringScsuFont
                                uefi_parser::HiiSibtType::StringScsuFont => {
                                    if let Ok((_, string)) =
                                        uefi_parser::sibt_string_scsu_font(block.Data.unwrap())
                                    {
                                        string_id_map.insert(current_string_index, string);
                                        current_string_index += 1;
                                    }
                                }
                                // 0x12: StringsScsu
                                uefi_parser::HiiSibtType::StringsScsu => {
                                    if let Ok((_, strings)) =
                                        uefi_parser::sibt_strings_scsu(block.Data.unwrap())
                                    {
                                        for string in strings {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                }
                                // 0x13: StringsScsuFont
                                uefi_parser::HiiSibtType::StringsScsuFont => {
                                    if let Ok((_, strings)) =
                                        uefi_parser::sibt_strings_scsu_font(block.Data.unwrap())
                                    {
                                        for string in strings {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                }
                                // 0x14: StringUcs2
                                uefi_parser::HiiSibtType::StringUcs2 => {
                                    if let Ok((_, string)) =
                                        uefi_parser::sibt_string_ucs2(block.Data.unwrap())
                                    {
                                        string_id_map.insert(current_string_index, string);
                                        current_string_index += 1;
                                    }
                                }
                                // 0x15: StringUcs2Font
                                uefi_parser::HiiSibtType::StringUcs2Font => {
                                    if let Ok((_, string)) =
                                        uefi_parser::sibt_string_ucs2_font(block.Data.unwrap())
                                    {
                                        string_id_map.insert(current_string_index, string);
                                        current_string_index += 1;
                                    }
                                }
                                // 0x16: StringsUcs2
                                uefi_parser::HiiSibtType::StringsUcs2 => {
                                    if let Ok((_, strings)) =
                                        uefi_parser::sibt_strings_ucs2(block.Data.unwrap())
                                    {
                                        for string in strings {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                }
                                // 0x17: StringsUcs2Font
                                uefi_parser::HiiSibtType::StringsUcs2Font => {
                                    if let Ok((_, strings)) =
                                        uefi_parser::sibt_strings_ucs2_font(block.Data.unwrap())
                                    {
                                        for string in strings {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                }
                                // 0x20: Duplicate
                                uefi_parser::HiiSibtType::Duplicate => {
                                    current_string_index += 1;
                                }
                                // 0x21: Skip2
                                uefi_parser::HiiSibtType::Skip2 => {
                                    // Manual parsing of Data as u16
                                    let count = block.Data.unwrap();
                                    current_string_index +=
                                        count[0] as u16 + 0x100 * count[1] as u16;
                                }
                                // 0x22: Skip1
                                uefi_parser::HiiSibtType::Skip1 => {
                                    // Manual parsing of Data as u8
                                    let count = block.Data.unwrap();
                                    current_string_index += count[0] as u16;
                                }
                                // Blocks below don't have any strings nor can they influence current_string_index
                                // No need to parse them here
                                // 0x30: Ext1
                                uefi_parser::HiiSibtType::Ext1 => {}
                                // 0x31: Ext2
                                uefi_parser::HiiSibtType::Ext2 => {}
                                // 0x32: Ext4
                                uefi_parser::HiiSibtType::Ext4 => {}
                                // Unknown SIBT block is impossible, because parsing will fail on it due to it's unknown length
                                uefi_parser::HiiSibtType::Unknown(_) => {}
                            }
                        }

                        // Add string
                        let string = (i, candidate.len(), string_package.Language, string_id_map);
                        strings.push(string);
                    }

                    i += candidate.len();
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    // No need to continue if there are no string packages found
    if strings.is_empty() {
        return (Vec::new(), Vec::new());
    }

    //
    // Search for all form packages in the input file
    //
    let mut forms = Vec::new();
    i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = uefi_parser::hii_form_package_candidate(&data[i..]) {
            if let Ok((_, package)) = uefi_parser::hii_package(candidate) {
                // Parse form package and obtain StringIds
                let mut string_ids: Vec<u16> = Vec::new();
                if let Ok((_, operations)) = uefi_parser::ifr_operations(package.Data.unwrap()) {
                    //let mut current_operation: usize = 0;
                    for operation in &operations {
                        //current_operation += 1;
                        //println!("Operation #{}, OpCode: {:?}, Length 0x{:X}, ScopeStart: {}", current_operation, operation.OpCode, operation.Length, operation.ScopeStart);
                        match operation.OpCode {
                            // 0x01: Form
                            uefi_parser::IfrOpcode::Form => {
                                if let Ok((_, form)) =
                                    uefi_parser::ifr_form(operation.Data.unwrap())
                                {
                                    string_ids.push(form.TitleStringId);
                                }
                            }
                            // 0x02: Subtitle
                            uefi_parser::IfrOpcode::Subtitle => {
                                if let Ok((_, sub)) =
                                    uefi_parser::ifr_subtitle(operation.Data.unwrap())
                                {
                                    string_ids.push(sub.PromptStringId);
                                    string_ids.push(sub.HelpStringId);
                                }
                            }
                            // 0x03: Text
                            uefi_parser::IfrOpcode::Text => {
                                if let Ok((_, txt)) = uefi_parser::ifr_text(operation.Data.unwrap())
                                {
                                    string_ids.push(txt.PromptStringId);
                                    string_ids.push(txt.HelpStringId);
                                    string_ids.push(txt.TextId);
                                }
                            }
                            // 0x04: Image
                            uefi_parser::IfrOpcode::Image => {}
                            // 0x05: OneOf
                            uefi_parser::IfrOpcode::OneOf => {
                                if let Ok((_, onf)) =
                                    uefi_parser::ifr_one_of(operation.Data.unwrap())
                                {
                                    string_ids.push(onf.PromptStringId);
                                    string_ids.push(onf.HelpStringId);
                                }
                            }
                            // 0x06: CheckBox
                            uefi_parser::IfrOpcode::CheckBox => {
                                if let Ok((_, cb)) =
                                    uefi_parser::ifr_check_box(operation.Data.unwrap())
                                {
                                    string_ids.push(cb.PromptStringId);
                                    string_ids.push(cb.HelpStringId);
                                }
                            }
                            // 0x07: Numeric
                            uefi_parser::IfrOpcode::Numeric => {
                                if let Ok((_, num)) =
                                    uefi_parser::ifr_numeric(operation.Data.unwrap())
                                {
                                    string_ids.push(num.PromptStringId);
                                    string_ids.push(num.HelpStringId);
                                }
                            }
                            // 0x08: Password
                            uefi_parser::IfrOpcode::Password => {
                                if let Ok((_, pw)) =
                                    uefi_parser::ifr_password(operation.Data.unwrap())
                                {
                                    string_ids.push(pw.PromptStringId);
                                    string_ids.push(pw.HelpStringId);
                                }
                            }
                            // 0x09: OneOfOption
                            uefi_parser::IfrOpcode::OneOfOption => {
                                if let Ok((_, opt)) =
                                    uefi_parser::ifr_one_of_option(operation.Data.unwrap())
                                {
                                    string_ids.push(opt.OptionStringId);
                                    match opt.Value {
                                        uefi_parser::IfrTypeValue::String(x) => {
                                            string_ids.push(x);
                                        }
                                        uefi_parser::IfrTypeValue::Action(x) => {
                                            string_ids.push(x);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // 0x0A: SuppressIf
                            uefi_parser::IfrOpcode::SuppressIf => {}
                            // 0x0B: Locked
                            uefi_parser::IfrOpcode::Locked => {}
                            // 0x0C: Action
                            uefi_parser::IfrOpcode::Action => {
                                if let Ok((_, act)) =
                                    uefi_parser::ifr_action(operation.Data.unwrap())
                                {
                                    string_ids.push(act.PromptStringId);
                                    string_ids.push(act.HelpStringId);
                                    if let Some(x) = act.ConfigStringId {
                                        string_ids.push(x);
                                    }
                                }
                            }
                            // 0x0D: ResetButton
                            uefi_parser::IfrOpcode::ResetButton => {
                                if let Ok((_, rst)) =
                                    uefi_parser::ifr_reset_button(operation.Data.unwrap())
                                {
                                    string_ids.push(rst.PromptStringId);
                                    string_ids.push(rst.HelpStringId);
                                }
                            }
                            // 0x0E: FormSet
                            uefi_parser::IfrOpcode::FormSet => {
                                if let Ok((_, form_set)) =
                                    uefi_parser::ifr_form_set(operation.Data.unwrap())
                                {
                                    string_ids.push(form_set.TitleStringId);
                                    string_ids.push(form_set.HelpStringId);
                                }
                            }
                            // 0x0F: Ref
                            uefi_parser::IfrOpcode::Ref => {
                                if let Ok((_, rf)) = uefi_parser::ifr_ref(operation.Data.unwrap()) {
                                    string_ids.push(rf.PromptStringId);
                                    string_ids.push(rf.HelpStringId);
                                }
                            }
                            // 0x10: NoSubmitIf
                            uefi_parser::IfrOpcode::NoSubmitIf => {
                                if let Ok((_, ns)) =
                                    uefi_parser::ifr_no_submit_if(operation.Data.unwrap())
                                {
                                    string_ids.push(ns.ErrorStringId);
                                }
                            }
                            // 0x11: InconsistentIf
                            uefi_parser::IfrOpcode::InconsistentIf => {
                                if let Ok((_, inc)) =
                                    uefi_parser::ifr_inconsistent_if(operation.Data.unwrap())
                                {
                                    string_ids.push(inc.ErrorStringId);
                                }
                            }
                            // 0x12: EqIdVal
                            uefi_parser::IfrOpcode::EqIdVal => {}
                            // 0x13: EqIdId
                            uefi_parser::IfrOpcode::EqIdId => {}
                            // 0x14: EqIdValList
                            uefi_parser::IfrOpcode::EqIdValList => {}
                            // 0x15: And
                            uefi_parser::IfrOpcode::And => {}
                            // 0x16: Or
                            uefi_parser::IfrOpcode::Or => {}
                            // 0x17: Not
                            uefi_parser::IfrOpcode::Not => {}
                            // 0x18: Rule
                            uefi_parser::IfrOpcode::Rule => {}
                            // 0x19: GrayOutIf
                            uefi_parser::IfrOpcode::GrayOutIf => {}
                            // 0x1A: Date
                            uefi_parser::IfrOpcode::Date => {
                                if let Ok((_, dt)) = uefi_parser::ifr_date(operation.Data.unwrap())
                                {
                                    string_ids.push(dt.PromptStringId);
                                    string_ids.push(dt.HelpStringId);
                                }
                            }
                            // 0x1B: Time
                            uefi_parser::IfrOpcode::Time => {
                                if let Ok((_, time)) =
                                    uefi_parser::ifr_time(operation.Data.unwrap())
                                {
                                    string_ids.push(time.PromptStringId);
                                    string_ids.push(time.HelpStringId);
                                }
                            }
                            // 0x1C: String
                            uefi_parser::IfrOpcode::String => {
                                if let Ok((_, st)) =
                                    uefi_parser::ifr_string(operation.Data.unwrap())
                                {
                                    string_ids.push(st.PromptStringId);
                                    string_ids.push(st.HelpStringId);
                                }
                            }
                            // 0x1D: Refresh
                            uefi_parser::IfrOpcode::Refresh => {}
                            // 0x1E: DisableIf
                            uefi_parser::IfrOpcode::DisableIf => {}
                            // 0x1F: Animation
                            uefi_parser::IfrOpcode::Animation => {}
                            // 0x20: ToLower
                            uefi_parser::IfrOpcode::ToLower => {}
                            // 0x21: ToUpper
                            uefi_parser::IfrOpcode::ToUpper => {}
                            // 0x22: Map
                            uefi_parser::IfrOpcode::Map => {}
                            // 0x23: OrderedList
                            uefi_parser::IfrOpcode::OrderedList => {
                                if let Ok((_, ol)) =
                                    uefi_parser::ifr_ordered_list(operation.Data.unwrap())
                                {
                                    string_ids.push(ol.PromptStringId);
                                    string_ids.push(ol.HelpStringId);
                                }
                            }
                            // 0x24: VarStore
                            uefi_parser::IfrOpcode::VarStore => {}
                            // 0x25: VarStoreNameValue
                            uefi_parser::IfrOpcode::VarStoreNameValue => {}
                            // 0x26: VarStoreEfi258
                            uefi_parser::IfrOpcode::VarStoreEfi => {}
                            // 0x27: VarStoreDevice
                            uefi_parser::IfrOpcode::VarStoreDevice => {
                                if let Ok((_, var_store)) =
                                    uefi_parser::ifr_var_store_device(operation.Data.unwrap())
                                {
                                    string_ids.push(var_store.DevicePathStringId);
                                }
                            }
                            // 0x28: Version
                            uefi_parser::IfrOpcode::Version => {}
                            // 0x29: End
                            uefi_parser::IfrOpcode::End => {}
                            // 0x2A: Match
                            uefi_parser::IfrOpcode::Match => {}
                            // 0x2B: Get
                            uefi_parser::IfrOpcode::Get => {}
                            // 0x2C: Set
                            uefi_parser::IfrOpcode::Set => {}
                            // 0x2D: Read
                            uefi_parser::IfrOpcode::Read => {}
                            // 0x2E: Write
                            uefi_parser::IfrOpcode::Write => {}
                            // 0x2F: Equal
                            uefi_parser::IfrOpcode::Equal => {}
                            // 0x30: NotEqual
                            uefi_parser::IfrOpcode::NotEqual => {}
                            // 0x31: GreaterThan
                            uefi_parser::IfrOpcode::GreaterThan => {}
                            // 0x32: GreaterEqual
                            uefi_parser::IfrOpcode::GreaterEqual => {}
                            // 0x33: LessThan
                            uefi_parser::IfrOpcode::LessThan => {}
                            // 0x34: LessEqual
                            uefi_parser::IfrOpcode::LessEqual => {}
                            // 0x35: BitwiseAnd
                            uefi_parser::IfrOpcode::BitwiseAnd => {}
                            // 0x36: BitwiseOr
                            uefi_parser::IfrOpcode::BitwiseOr => {}
                            // 0x37: BitwiseNot
                            uefi_parser::IfrOpcode::BitwiseNot => {}
                            // 0x38: ShiftLeft
                            uefi_parser::IfrOpcode::ShiftLeft => {}
                            // 0x39: ShiftRight
                            uefi_parser::IfrOpcode::ShiftRight => {}
                            // 0x3A: Add
                            uefi_parser::IfrOpcode::Add => {}
                            // 0x3B: Substract
                            uefi_parser::IfrOpcode::Substract => {}
                            // 0x3C: Multiply
                            uefi_parser::IfrOpcode::Multiply => {}
                            // 0x3D: Divide
                            uefi_parser::IfrOpcode::Divide => {}
                            // 0x3E: Modulo
                            uefi_parser::IfrOpcode::Modulo => {}
                            // 0x3F: RuleRef
                            uefi_parser::IfrOpcode::RuleRef => {}
                            // 0x40: QuestionRef1
                            uefi_parser::IfrOpcode::QuestionRef1 => {}
                            // 0x41: QuestionRef2
                            uefi_parser::IfrOpcode::QuestionRef2 => {}
                            // 0x42: Uint8
                            uefi_parser::IfrOpcode::Uint8 => {}
                            // 0x43: Uint16
                            uefi_parser::IfrOpcode::Uint16 => {}
                            // 0x44: Uint32
                            uefi_parser::IfrOpcode::Uint32 => {}
                            // 0x45: Uint64
                            uefi_parser::IfrOpcode::Uint64 => {}
                            // 0x46: True
                            uefi_parser::IfrOpcode::True => {}
                            // 0x47: False
                            uefi_parser::IfrOpcode::False => {}
                            // 0x48: ToUint
                            uefi_parser::IfrOpcode::ToUint => {}
                            // 0x49: ToString
                            uefi_parser::IfrOpcode::ToString => {}
                            // 0x4A: ToBoolean
                            uefi_parser::IfrOpcode::ToBoolean => {}
                            // 0x4B: Mid
                            uefi_parser::IfrOpcode::Mid => {}
                            // 0x4C: Find
                            uefi_parser::IfrOpcode::Find => {}
                            // 0x4D: Token
                            uefi_parser::IfrOpcode::Token => {}
                            // 0x4E: StringRef1
                            uefi_parser::IfrOpcode::StringRef1 => {
                                if let Ok((_, st)) =
                                    uefi_parser::ifr_string_ref_1(operation.Data.unwrap())
                                {
                                    string_ids.push(st.StringId);
                                }
                            }
                            // 0x4F: StringRef2
                            uefi_parser::IfrOpcode::StringRef2 => {}
                            // 0x50: Conditional
                            uefi_parser::IfrOpcode::Conditional => {}
                            // 0x51: QuestionRef3
                            uefi_parser::IfrOpcode::QuestionRef3 => {
                                if operation.Data.is_some() {
                                    if let Ok((_, qr)) =
                                        uefi_parser::ifr_question_ref_3(operation.Data.unwrap())
                                    {
                                        if let Some(x) = qr.DevicePathId {
                                            string_ids.push(x);
                                        }
                                    }
                                }
                            }
                            // 0x52: Zero
                            uefi_parser::IfrOpcode::Zero => {}
                            // 0x53: One
                            uefi_parser::IfrOpcode::One => {}
                            // 0x54: Ones
                            uefi_parser::IfrOpcode::Ones => {}
                            // 0x55: Undefined
                            uefi_parser::IfrOpcode::Undefined => {}
                            // 0x56: Length
                            uefi_parser::IfrOpcode::Length => {}
                            // 0x57: Dup
                            uefi_parser::IfrOpcode::Dup => {}
                            // 0x58: This
                            uefi_parser::IfrOpcode::This => {}
                            // 0x59: Span
                            uefi_parser::IfrOpcode::Span => {}
                            // 0x5A: Value
                            uefi_parser::IfrOpcode::Value => {}
                            // 0x5B: Default
                            uefi_parser::IfrOpcode::Default => {
                                if let Ok((_, def)) =
                                    uefi_parser::ifr_default(operation.Data.unwrap())
                                {
                                    match def.Value {
                                        uefi_parser::IfrTypeValue::String(x) => {
                                            string_ids.push(x);
                                        }
                                        uefi_parser::IfrTypeValue::Action(x) => {
                                            string_ids.push(x);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // 0x5C: DefaultStore
                            uefi_parser::IfrOpcode::DefaultStore => {
                                if let Ok((_, default_store)) =
                                    uefi_parser::ifr_default_store(operation.Data.unwrap())
                                {
                                    string_ids.push(default_store.NameStringId);
                                }
                            }
                            // 0x5D: FormMap
                            uefi_parser::IfrOpcode::FormMap => {
                                if let Ok((_, form_map)) =
                                    uefi_parser::ifr_form_map(operation.Data.unwrap())
                                {
                                    for method in form_map.Methods {
                                        string_ids.push(method.MethodTitleId);
                                    }
                                }
                            }
                            // 0x5E: Catenate
                            uefi_parser::IfrOpcode::Catenate => {}
                            // 0x5F: GUID
                            uefi_parser::IfrOpcode::Guid => {
                                if let Ok((_, guid)) =
                                    uefi_parser::ifr_guid(operation.Data.unwrap())
                                {
                                    // This manual parsing here is ugly and can ultimately be done using nom,
                                    // but it's done already and not that important anyway
                                    match guid.Guid {
                                        uefi_parser::IFR_TIANO_GUID => {
                                            if let Ok((_, edk2)) =
                                                uefi_parser::ifr_guid_edk2(guid.Data)
                                            {
                                                match edk2.ExtendedOpCode {
                                                    uefi_parser::IfrEdk2ExtendOpCode::Banner => {
                                                        if let Ok((_, banner)) =
                                                            uefi_parser::ifr_guid_edk2_banner(
                                                                edk2.Data,
                                                            )
                                                        {
                                                            string_ids.push(banner.TitleId);
                                                        }
                                                    }
                                                    uefi_parser::IfrEdk2ExtendOpCode::Label => {}
                                                    uefi_parser::IfrEdk2ExtendOpCode::Timeout => {}
                                                    uefi_parser::IfrEdk2ExtendOpCode::Class => {}
                                                    uefi_parser::IfrEdk2ExtendOpCode::SubClass => {}
                                                    uefi_parser::IfrEdk2ExtendOpCode::Unknown(
                                                        _,
                                                    ) => {}
                                                }
                                            }
                                        }
                                        uefi_parser::IFR_FRAMEWORK_GUID => {
                                            if let Ok((_, edk)) =
                                                uefi_parser::ifr_guid_edk(guid.Data)
                                            {
                                                match edk.ExtendedOpCode {
                                                    uefi_parser::IfrEdkExtendOpCode::OptionKey => {}
                                                    uefi_parser::IfrEdkExtendOpCode::VarEqName => {
                                                        if edk.Data.len() == 2 {
                                                            let name_id = edk.Data[1] as u16 * 100
                                                                + edk.Data[0] as u16;
                                                            string_ids.push(name_id);
                                                        }
                                                    }
                                                    uefi_parser::IfrEdkExtendOpCode::Unknown(_) => {
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // 0x60: Security
                            uefi_parser::IfrOpcode::Security => {}
                            // 0x61: ModalTag
                            uefi_parser::IfrOpcode::ModalTag => {}
                            // 0x62: RefreshId
                            uefi_parser::IfrOpcode::RefreshId => {}
                            // 0x63: WarningIf
                            uefi_parser::IfrOpcode::WarningIf => {
                                if let Ok((_, warn)) =
                                    uefi_parser::ifr_warning_if(operation.Data.unwrap())
                                {
                                    string_ids.push(warn.WarningStringId);
                                }
                            }
                            // 0x64: Match2
                            uefi_parser::IfrOpcode::Match2 => {}
                            // Unknown operation
                            uefi_parser::IfrOpcode::Unknown(_) => {}
                        }
                    }
                }

                // Find min and max StringId, and the number of unique ones
                string_ids.sort();
                string_ids.dedup();
                if !string_ids.is_empty() {
                    // Add the required information to forms
                    let form = (
                        i,
                        candidate.len(),
                        string_ids.len(),
                        *string_ids.first().unwrap(),
                        *string_ids.last().unwrap(),
                    );
                    forms.push(form);
                }

                i += candidate.len();
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    // No need to continue if no forms are found
    if forms.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // Construct return value
    let mut result_strings = Vec::new();
    let mut result_forms = Vec::new();
    for string in &strings {
        result_strings.push(StringPackage {
            offset: string.0,
            length: string.1,
            language: string.2.clone(),
            string_id_map: string.3.clone(),
        });
    }
    for form in &forms {
        result_forms.push(FormPackage {
            offset: form.0,
            length: form.1,
            used_strings: form.2,
            min_string_id: form.3,
            max_string_id: form.4,
        });
    }

    (result_strings, result_forms)
}


fn uefi_ifr_extract_to_string(
    data: &[u8],
    form_pkg: &FormPackage,
    string_pkg: &StringPackage,
    verbose: bool,
) -> String {
    let mut text: Vec<u8> = Vec::new();
    let strings_map = &string_pkg.string_id_map;

    // Version and mode
    writeln!(
        &mut text,
        "Program version: {}, Extraction mode: UEFI",
        env!("CARGO_PKG_VERSION")
    )
    .unwrap();

    // Locate the UEFI form package
    if let Ok((_, candidate)) = uefi_parser::hii_form_package_candidate(&data[form_pkg.offset..]) {
        if let Ok((_, package)) = uefi_parser::hii_package(candidate) {
            if let Ok((_, operations)) = uefi_parser::ifr_operations(package.Data.unwrap()) {
                let mut scope_depth = 0usize;
                let mut offset = form_pkg.offset + 4; // UEFI HII form header
                use uefi_parser::IfrOpcode::*;
                for op in &operations {
                    // Decrease scope on End opcode
                    if op.OpCode == End && scope_depth > 0 {
                        scope_depth -= 1;
                    }
                    if verbose {
                        write!(&mut text, "0x{:X}: ", offset).unwrap();
                    }
                    write!(
                        &mut text,
                        "{:width$}{:?} ",
                        "",            // first positional: the empty-string indent
                        op.OpCode,     // second positional: the opcode
                        width = scope_depth,  // named parameter for the dynamic width
                    ).unwrap();

                    // Increase scope on ScopeStart
                    if op.ScopeStart {
                        scope_depth += 1;
                    }

                    if let Some(d) = op.Data {
                        match op.OpCode {
                            Form => if let Ok((_, f)) = uefi_parser::ifr_form(d) {
                                write!(
                                    &mut text,
                                    "FormId: 0x{:X}, Title: \"{}\"",
                                    f.FormId,
                                    strings_map.get(&f.TitleStringId).unwrap_or(&"InvalidId".into())
                                )
                                .unwrap();
                            },
                            Subtitle => if let Ok((_, s)) = uefi_parser::ifr_subtitle(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", Flags: 0x{:X}",
                                    strings_map.get(&s.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&s.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    s.Flags
                                )
                                .unwrap();
                            },
                            Text => if let Ok((_, t)) = uefi_parser::ifr_text(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", Text: \"{}\"",
                                    strings_map.get(&t.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&t.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&t.TextId).unwrap_or(&"InvalidId".into())
                                )
                                .unwrap();
                            },
                            Image => if let Ok((_, img)) = uefi_parser::ifr_image(d) {
                                write!(&mut text, "ImageId: 0x{:X}", img.ImageId).unwrap();
                            },
                            OneOf => if let Ok((_, o)) = uefi_parser::ifr_one_of(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, \
                                     VarStoreId: 0x{:X}, VarOffset: 0x{:X}, Flags: 0x{:X}",
                                    strings_map.get(&o.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&o.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    o.QuestionFlags, o.QuestionId, o.VarStoreId, o.VarStoreInfo, o.Flags
                                )
                                .unwrap();
                            
                                write_min_max(&mut text, &o.MinMaxStepData8, 8);
                                write_min_max(&mut text, &o.MinMaxStepData16, 16);
                                write_min_max(&mut text, &o.MinMaxStepData32, 32);
                                write_min_max(&mut text, &o.MinMaxStepData64, 64);
                            
                            },
                            CheckBox => if let Ok((_, c)) = uefi_parser::ifr_check_box(d) {
                                write!(
                                    &mut text,
                                    "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarOffset: 0x{:X}, Flags: 0x{:X}",
                                    strings_map.get(&c.PromptStringId).unwrap_or(&"InvalidId".into()),
                                    strings_map.get(&c.HelpStringId).unwrap_or(&"InvalidId".into()),
                                    c.QuestionFlags,
                                    c.QuestionId,
                                    c.VarStoreId,
                                    c.VarStoreInfo,
                                    c.Flags
                                )
                                .unwrap();
                                // Default flags
                                let defaults = [(uefi_parser::IfrCheckBoxDefaultFlags::Default, "Default"), (uefi_parser::IfrCheckBoxDefaultFlags::MfgDefault, "MfgDefault")];
                                for (flag, name) in defaults {
                                    write!(
                                        &mut text,
                                        ", {name}: {}",
                                        if (c.Flags & (flag as u8)) != 0 { "Enabled" } else { "Disabled" }
                                    )
                                    .unwrap();
                                }
                            },
                            // ... handle other opcodes similarly ...
                            _ => {}
                        }
                    }

                    offset += op.Length as usize;
                    writeln!(&mut text).unwrap();
                }
            }
        }
    }

    String::from_utf8(text).unwrap_or_default()
}

/// This module is a Python submodule implemented in Rust.
#[pymodule]
fn pyifrextractor(
    py: Python,
    m: &PyModule,
) -> PyResult<()> {
    m.add_class::<StringPackage>()?;
    m.add_class::<FormPackage>()?;
    m.add_function(wrap_pyfunction!(find_framework_packages_py, m)?)?;
    m.add_function(wrap_pyfunction!(extract_framework_ifr_py, m)?)?;
    m.add_function(wrap_pyfunction!(find_uefi_packages_py, m)?)?;
    m.add_function(wrap_pyfunction!(extract_uefi_ifr_py, m)?)?;
    Ok(())
}