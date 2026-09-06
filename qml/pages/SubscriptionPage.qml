import QtQuick 2.12
import QtQuick.Layouts 1.12
import Lomiri.Components 1.3

Page {
    id: page
    property var app
    property bool busy: false
    property bool alive: true
    property string pending: ""
    property string generation: ""
    property string loginCode: ""
    property string message: ""
    property bool signedIn: false
    header: PageHeader { title: i18n.tr("ChatGPT subscription") }

    function call(request, done) {
        busy = true;
        app.apiSubscription(request, function(r) {
            if (!page || !page.alive) return;
            page.busy = false;
            if (!r || r.ok !== true) { page.message = page.app.describeError(r); return; }
            done(r);
        });
    }
    function status() {
        call({action: "status"}, function(r) {
            page.signedIn = r.state === "signed_in";
            page.generation = r.generation || "";
            page.message = page.signedIn ? i18n.tr("Signed in. Verify your chosen model, then save.") : i18n.tr("Sign in to continue. Enable device login in ChatGPT security settings if needed.");
            if (!modelField.text) modelField.text = r.model || "gpt-5.6-luna";
            if (!effortField.text) effortField.text = r.effort || "high";
        });
    }
    function start() {
        poll.stop();
        call({action: "start"}, function(r) {
            page.pending = r.pending; page.loginCode = r.code;
            page.message = i18n.tr("Open ChatGPT sign-in and enter this code. Expires in 15 minutes.");
            poll.interval = Math.max(1, r.interval || 5) * 1000; poll.start();
        });
    }
    function check() {
        var id = pending;
        if (!id || busy) return;
        call({action: "poll", pending: id}, function(r) {
            if (page.pending !== id) return;
            if (r.state === "signed_in") { page.pending = ""; page.loginCode = ""; page.status(); }
            else { poll.interval = Math.max(1, r.interval || 5) * 1000; poll.start(); }
        });
    }
    function cancel() {
        poll.stop(); var id = pending;
        call({action: "cancel", pending: id}, function() { page.pending = ""; page.loginCode = ""; page.status(); });
    }
    function save() {
        var m = modelField.text.trim(), e = effortField.text.trim(), g = generation;
        call({action: "probe", model: m, effort: e, generation: g}, function(r) {
            page.call({action: "select", model: m, effort: e, generation: r.generation, activate: true}, function() {
                page.message = i18n.tr("ChatGPT selected. Start Briglia when ready.");
                page.app.refresh();
            });
        });
    }
    Timer { id: poll; repeat: false; onTriggered: page.check() }
    Component.onCompleted: status()
    Component.onDestruction: {
        alive = false; poll.stop();
        // Pending handles are inert after cancellation/expiry. No tokens enter QML.
        if (pending) app.apiSubscription({action: "cancel", pending: pending}, function() {});
    }
    Flickable {
        anchors { top: page.header.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
        contentHeight: column.height + units.gu(4)
        clip: true
        ColumnLayout {
            id: column
            anchors { top: parent.top; topMargin: units.gu(2); horizontalCenter: parent.horizontalCenter }
            width: parent.width - units.gu(4)
            spacing: units.gu(1.5)
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: i18n.tr("Use your ChatGPT subscription for the main agent. Subscription limits apply; quota is currently unknown. Web search, voice and image tools still use separately billed API keys.") }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; textFormat: Text.PlainText; text: page.message }
            Label { Layout.fillWidth: true; textFormat: Text.PlainText; text: page.loginCode; font.bold: true }
            Button { Layout.fillWidth: true; text: i18n.tr("Sign in / re-login"); enabled: !page.busy && !page.pending; onClicked: page.start() }
            Button { Layout.fillWidth: true; text: i18n.tr("Open ChatGPT sign-in"); visible: page.pending !== ""; onClicked: Qt.openUrlExternally("https://auth.openai.com/codex/device") }
            Button { Layout.fillWidth: true; text: i18n.tr("Check sign-in again"); visible: page.pending !== ""; enabled: !page.busy; onClicked: page.check() }
            Button { Layout.fillWidth: true; text: i18n.tr("Cancel login"); visible: page.pending !== ""; enabled: !page.busy; onClicked: page.cancel() }
            TextField { id: modelField; Layout.fillWidth: true; enabled: !page.busy; placeholderText: i18n.tr("Model, e.g. gpt-5.6-luna") }
            TextField { id: effortField; Layout.fillWidth: true; enabled: !page.busy; placeholderText: i18n.tr("Reasoning effort, e.g. high") }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: i18n.tr("Stop Briglia before changing its active provider. An unmanaged terminal process must be stopped in its terminal. Restart after saving.") }
            Button { Layout.fillWidth: true; text: i18n.tr("Stop background service"); enabled: !page.busy; onClicked: { page.busy = true; page.app.pyCall("systemctl_user", ["stop"], function(r) { if (!page || !page.alive) return; page.busy = false; page.message = r && r.ok === true ? i18n.tr("Service stopped.") : page.app.describeError(r); page.app.refresh(); }); } }
            Button { Layout.fillWidth: true; text: i18n.tr("Verify model and use ChatGPT"); enabled: !page.busy && page.signedIn && !page.pending; onClicked: page.save() }
            Button { Layout.fillWidth: true; text: i18n.tr("Sign out locally"); enabled: !page.busy; onClicked: { poll.stop(); page.call({action: "logout"}, function() { page.pending = ""; page.loginCode = ""; page.status(); page.app.refresh(); }); } }
            Button { Layout.fillWidth: true; text: i18n.tr("Start background service"); enabled: !page.busy; onClicked: { page.busy = true; page.app.pyCall("systemctl_user", ["start"], function(r) { if (!page || !page.alive) return; page.busy = false; page.message = r && r.ok === true ? i18n.tr("Service started.") : page.app.describeError(r); page.app.refresh(); }); } }
            Button { Layout.fillWidth: true; text: i18n.tr("Back to setup"); enabled: !page.busy; onClicked: page.app.popPage() }
        }
    }
}
