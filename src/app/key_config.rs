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
    #[keybindings["k", "Up"]]
    PktUp,
    /// Packet window down
    #[keybindings["j", "Down"]]
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
    #[keybindings["w"]]
    DtlUp,
    /// Details window down
    #[keybindings["s"]]
    DtlDown,
    /// Hex window up
    #[keybindings["e"]]
    HexUp,
    /// Hex window down
    #[keybindings["d"]]
    HexDown,
}
