// NEFI OS — layout predefinito del desktop
var wallpaper = "file:///usr/share/wallpapers/NEFI/";

// Sfondo su tutti i desktop
var desks = desktopsForActivity(currentActivity());
for (var i = 0; i < desks.length; i++) {
    desks[i].wallpaperPlugin = "org.kde.image";
    desks[i].currentConfigGroup = ["Wallpaper", "org.kde.image", "General"];
    desks[i].writeConfig("Image", wallpaper);
}

// ── Barra in alto ─────────────────────────────────────
var top = new Panel;
top.location = "top";
top.height = Math.round(gridUnit * 1.6);
top.floating = false;

// Due spaziatori flessibili: l'orologio resta centrato sullo schermo
top.addWidget("org.kde.plasma.panelspacer");
var clock = top.addWidget("org.kde.plasma.digitalclock");
clock.currentConfigGroup = ["Appearance"];
clock.writeConfig("showDate", true);
clock.writeConfig("dateDisplayFormat", "BesideTime");
clock.writeConfig("dateFormat", "custom");
clock.writeConfig("customDateFormat", "dd MMM yyyy");
top.addWidget("org.kde.plasma.panelspacer");

// Destra: RAM, system tray (batteria, Wi-Fi, Bluetooth, audio), meteo
var ram = top.addWidget("org.kde.plasma.systemmonitor.memory");
ram.currentConfigGroup = ["Appearance"];
ram.writeConfig("chartFace", "org.kde.ksysguard.textonly");
top.addWidget("org.kde.plasma.systemtray");
top.addWidget("org.kde.plasma.weather");

// ── Dock in basso: compatta, centrata, flottante ──────
var dock = new Panel;
dock.location = "bottom";
dock.height = Math.round(gridUnit * 2.6);
dock.alignment = "center";
dock.minimumLength = gridUnit * 10;
dock.maximumLength = gridUnit * 34;
dock.lengthMode = "fit";
dock.floating = true;
dock.hiding = "dodgewindows";

var menu = dock.addWidget("org.kde.plasma.kickoff");
menu.currentConfigGroup = ["General"];
menu.writeConfig("icon", "nefi-os");

dock.addWidget("org.kde.plasma.marginsseparator");

var tasks = dock.addWidget("org.kde.plasma.icontasks");
tasks.currentConfigGroup = ["General"];
tasks.writeConfig("launchers", [
    "applications:nefi-security-center.desktop",
    "applications:org.kde.dolphin.desktop",
    "applications:firefox-esr.desktop",
    "applications:org.kde.konsole.desktop",
    "applications:org.kde.kate.desktop",
    "applications:org.keepassxc.KeePassXC.desktop",
    "applications:systemsettings.desktop"
]);
