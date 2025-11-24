use crossterm_keybind::KeyBind;

#[derive(KeyBind)]
/// Click events in app
pub enum KeyEvent {
    /// Apply a packet filter
    #[keybindings["Enter"]]
    ApplyFilter,
    /// Clear packet filter
    #[keybindings["Esc"]]
    ClearFilter,
    /// Close app
    #[keybindings["Control+c", "Q", "q"]]
    Quit,
    /// Packet window up
    #[keybindings["k"]]
    PktUp,
    /// Packet window down
    #[keybindings["j"]]
    PktDown,
    /// Packet window page up
    #[keybindings["PageUp"]]
    PktPageUp,
    /// Packet window page down
    #[keybindings["PageDown"]]
    PktPageDown,
    /// Packet window page jump to head
    #[keybindings["Home"]]
    PktHome,
    /// Packet window page jump to end
    #[keybindings["End"]]
    PktEnd,
    /// Details window up
    #[keybindings["Control+k"]]
    DtlUp,
    /// Details window down
    #[keybindings["Control+j"]]
    DtlDown,
    /// Hex window up
    #[keybindings["Shift+k"]]
    HexUp,
    /// Hex window down
    #[keybindings["Shift+j"]]
    HexDown,
}
