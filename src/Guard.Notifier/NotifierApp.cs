using System.Security.Principal;
using Guard.Service.Status;

namespace Guard.Notifier
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            // One notifier per logon session.
            using Mutex single = new(initiallyOwned: true, @"Local\ComsPcGuardNotifier", out bool created);
            if (!created)
            {
                return;
            }

            string statusPath = args.Length == 2 && args[0] == "--status"
                ? Path.GetFullPath(args[1])
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ComsPcGuard", "status", "status.json");
            ApplicationConfiguration.Initialize();
            Application.Run(new NotifierContext(statusPath, WindowsIdentity.GetCurrent().User?.Value ?? string.Empty));
        }
    }

    /// <summary>Tray icon for a logged-on member: shows their own restriction state and pops up changes. Read-only.</summary>
    internal sealed class NotifierContext : ApplicationContext
    {
        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);

        private readonly string _statusPath;
        private readonly string _userSid;
        private readonly NotifyIcon _icon;
        private readonly System.Windows.Forms.Timer _timer;
        private readonly HashSet<string> _warned = [];
        private GuardMemberStatus? _previous;
        private GuardStatusSnapshot? _snapshot;
        private StatusForm? _form;

        internal NotifierContext(string statusPath, string userSid)
        {
            _statusPath = statusPath;
            _userSid = userSid;
            ContextMenuStrip menu = new();
            _ = menu.Items.Add("내 상태 보기", null, (_, _) => ShowStatus());
            _ = menu.Items.Add("알림 닫기", null, (_, _) => ExitThread());
            _icon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = "COMS PC Guard",
                ContextMenuStrip = menu,
                Visible = true,
            };
            _icon.DoubleClick += (_, _) => ShowStatus();
            _timer = new System.Windows.Forms.Timer { Interval = (int)PollInterval.TotalMilliseconds };
            _timer.Tick += (_, _) => Refresh();
            _timer.Start();
            Refresh();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _timer.Dispose();
                _icon.Visible = false;
                _icon.Dispose();
                _form?.Dispose();
            }

            base.Dispose(disposing);
        }

        private void Refresh()
        {
            _snapshot = GuardStatusFile.TryRead(_statusPath);
            GuardMemberStatus? me = _snapshot?.Members.FirstOrDefault(member => member.Sid == _userSid);
            if (_snapshot is null)
            {
                _icon.Text = "COMS PC Guard: 상태를 읽을 수 없어요";
                return;
            }

            if (me is null)
            {
                _icon.Text = "COMS PC Guard: 제한 대상이 아니에요";
                _previous = null;
                return;
            }

            TimeZoneInfo zone = Zone(_snapshot.TimeZoneId);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            int restricted = me.Apps.Count(app => app.Decision == Core.Policies.PolicyDecisionKind.Restricted);
            string tip = restricted > 0 ? $"COMS PC Guard: 게임 {restricted}개 제한 중" : "COMS PC Guard: 지금은 제한 없음";
            _icon.Text = tip.Length > 63 ? tip[..63] : tip;
            IReadOnlyList<string> alerts = GuardStatusMessages.Alerts(_previous, me, now, zone, _warned);
            if (alerts.Count > 0)
            {
                _icon.ShowBalloonTip(10000, "COMS PC Guard", string.Join(Environment.NewLine, alerts), ToolTipIcon.Info);
            }

            _previous = me;
            _form?.Render(me, _snapshot, zone);
        }

        private void ShowStatus()
        {
            Refresh();
            if (_form is null)
            {
                _form = new StatusForm();
                _form.FormClosed += (_, _) => _form = null;
            }

            GuardMemberStatus? me = _snapshot?.Members.FirstOrDefault(member => member.Sid == _userSid);
            _form.Render(me, _snapshot, Zone(_snapshot?.TimeZoneId));
            _form.Show();
            _ = _form.Focus();
        }

        private static TimeZoneInfo Zone(string? id)
        {
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(id ?? "Korea Standard Time");
            }
            catch (TimeZoneNotFoundException)
            {
                return TimeZoneInfo.Local;
            }
        }
    }

    /// <summary>Small read-only window listing the member's games and states.</summary>
    internal sealed class StatusForm : Form
    {
        private readonly Label _summary = new() { Dock = DockStyle.Top, Height = 48, Padding = new Padding(12, 12, 12, 0), Font = new Font("Malgun Gothic", 11F, FontStyle.Bold) };
        private readonly ListBox _list = new() { Dock = DockStyle.Fill, Font = new Font("Malgun Gothic", 10F), BorderStyle = BorderStyle.None, IntegralHeight = false };

        internal StatusForm()
        {
            Text = "COMS PC Guard - 내 상태";
            Width = 460;
            Height = 320;
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            Padding = new Padding(8);
            Controls.Add(_list);
            Controls.Add(_summary);
        }

        internal void Render(GuardMemberStatus? me, GuardStatusSnapshot? snapshot, TimeZoneInfo zone)
        {
            _list.Items.Clear();
            if (snapshot is null)
            {
                _summary.Text = "상태를 아직 읽을 수 없어요.";
                return;
            }

            if (me is null)
            {
                _summary.Text = "이 계정은 제한 대상이 아니에요.";
                return;
            }

            _summary.Text = snapshot.Emergency
                ? "긴급 제한 중이에요."
                : snapshot.AuditOnly ? "지금은 시험 운영 중이라 막지 않아요." : $"{me.Name} 님의 게임 상태";
            DateTimeOffset now = DateTimeOffset.UtcNow;
            foreach (GuardAppStatus app in me.Apps)
            {
                _ = _list.Items.Add(GuardStatusMessages.Describe(app, now, zone));
            }
        }
    }
}
