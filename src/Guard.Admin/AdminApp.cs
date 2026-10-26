using System.Globalization;
using Guard.Service.AppLocker;
using Guard.Service.Audit;
using Guard.Service.Configuration;
using Guard.Service.Status;
using Guard.Windows;

namespace Guard.Admin
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            // --data lets the lab and tests point the screen at a scratch folder instead of the protected ProgramData one.
            string dataDirectory = args is ["--data", string directory]
                ? Path.GetFullPath(directory)
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ComsPcGuard");
            ApplicationConfiguration.Initialize();
            using PowerShellAppLockerGateway gateway = new();
            using AdminForm form = new(dataDirectory, gateway, WindowsAccounts.CurrentUserSid() ?? string.Empty);
            Application.Run(form);
        }
    }

    /// <summary>A list or drop-down entry; <see cref="Key"/> null means "everyone"/"every game".</summary>
    internal sealed record Choice(string? Key, string Text)
    {
        public override string ToString()
        {
            return Text;
        }
    }

    internal sealed record AccountChoice(LocalAccount Account)
    {
        public override string ToString()
        {
            return Account.FullName is { Length: > 0 } full && full != Account.Name ? $"{Account.Name} ({full})" : Account.Name;
        }
    }

    /// <summary>
    /// The Owner screen: the same edits as the guard command line, with buttons. Every change re-reads the policy file, checks
    /// the Owner, edits, and saves atomically, so the command line and this screen can be used side by side without losing edits.
    /// </summary>
    internal sealed class AdminForm : Form
    {
        private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(3);
        private static readonly Font BodyFont = new("Malgun Gothic", 10F);
        private static readonly Font HeadingFont = new("Malgun Gothic", 10.5F, FontStyle.Bold);
        private static readonly DayOfWeek[] Week = [DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday];

        private readonly string _policyPath;
        private readonly string _statusPath;
        private readonly PowerShellAppLockerGateway _gateway;
        private readonly string _userSid;
        private readonly List<Control> _editControls = [];
        private readonly System.Windows.Forms.Timer _timer = new() { Interval = 10_000 };

        private readonly Label _header = new() { Dock = DockStyle.Top, Height = 34, Font = HeadingFont, Padding = new Padding(10, 8, 10, 0) };
        private readonly ToolStripStatusLabel _message = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };

        private readonly Label _statusSummary = new() { AutoSize = false, Height = 110, Padding = new Padding(4) };
        private readonly ListBox _statusList = new() { IntegralHeight = false };
        private readonly CheckBox _enforce = new() { Text = "차단 모드 (끄면 '시험 운영': 막지 않고 기록만 해요)", AutoSize = true };
        private readonly CheckBox _emergency = new() { Text = "긴급 제한 (시간표와 상관없이 지금 바로 모든 게임 막기)", AutoSize = true };
        private readonly Button _createPolicy = Act("정책 새로 만들기", (_, _) => { });

        private readonly ComboBox _accountPicker = new() { Width = 260, DropDownStyle = ComboBoxStyle.DropDown };
        private readonly ListBox _members = new() { IntegralHeight = false };

        private readonly TextBox _appName = new() { Width = 200, PlaceholderText = "비우면 게임 이름 자동" };
        private readonly ListBox _apps = new() { IntegralHeight = false };

        private readonly ComboBox _grantMember = new() { Width = 170, DropDownStyle = ComboBoxStyle.DropDownList };
        private readonly ComboBox _grantApp = new() { Width = 170, DropDownStyle = ComboBoxStyle.DropDownList };
        private readonly ComboBox _grantDuration = new() { Width = 130, DropDownStyle = ComboBoxStyle.DropDownList };
        private readonly ListBox _grants = new() { IntegralHeight = false };

        private readonly CheckBox[] _days = [.. Week.Select(day => new CheckBox { Text = KoreanDay(day), AutoSize = true, Margin = new Padding(3, 6, 6, 3) })];
        private readonly DateTimePicker _start = TimePicker();
        private readonly DateTimePicker _end = TimePicker();
        private readonly CheckBox _allDay = new() { Text = "하루 종일", AutoSize = true, Margin = new Padding(12, 6, 3, 3) };
        private readonly DateTimePicker _holidayDate = new() { Format = DateTimePickerFormat.Long, Width = 200 };
        private readonly ListBox _holidays = new() { IntegralHeight = false };

        private readonly GuardAuditLog _audit;
        private readonly ComboBox _logPeriod = new() { Width = 130, DropDownStyle = ComboBoxStyle.DropDownList };
        private readonly Label _logCount = new() { AutoSize = true, Margin = new Padding(12, 8, 3, 3) };
        private readonly ListView _logView = new() { View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable };
        private readonly TabPage _logPage;

        private GuardPolicyDocument? _document;
        private bool _rendering;

        internal AdminForm(string dataDirectory, PowerShellAppLockerGateway gateway, string userSid)
        {
            _policyPath = Path.Combine(dataDirectory, "policy.json");
            _statusPath = Path.Combine(dataDirectory, "status", "status.json");
            _gateway = gateway;
            _userSid = userSid;
            _audit = GuardAuditLog.ForDataDirectory(dataDirectory);

            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "COMS PC Guard 관리";
            Font = BodyFont;
            Width = 820;
            Height = 600;
            MinimumSize = new Size(700, 480);
            StartPosition = FormStartPosition.CenterScreen;
            Icon = SystemIcons.Shield;

            TabControl tabs = new() { Dock = DockStyle.Fill, Padding = new Point(14, 5) };
            _logPage = LogPage();
            tabs.TabPages.AddRange([StatusPage(), MembersPage(), GamesPage(), GrantsPage(), SchedulePage(), _logPage]);
            tabs.SelectedIndexChanged += (_, _) =>
            {
                if (tabs.SelectedTab == _logPage)
                {
                    RenderLog();
                }
            };
            StatusStrip strip = new();
            _ = strip.Items.Add(_message);
            Controls.Add(tabs);
            Controls.Add(_header);
            Controls.Add(strip);
            ResumeLayout(performLayout: true);

            _enforce.CheckedChanged += (_, _) => OnEnforceChanged();
            _emergency.CheckedChanged += (_, _) => OnEmergencyChanged();
            _allDay.CheckedChanged += (_, _) => _start.Enabled = _end.Enabled = !_allDay.Checked && CanEdit;
            _timer.Tick += (_, _) => OnTimer();
            _createPolicy.Click += (_, _) => OfferToCreatePolicy();
        }

        private bool CanEdit => _document is not null && _document.OwnerSid == _userSid;

        protected override async void OnShown(EventArgs e)
        {
            base.OnShown(e);
            ReloadPolicy();
            if (_document is null && !File.Exists(_policyPath) && !File.Exists(GuardPolicyStore.BackupPath(_policyPath)))
            {
                OfferToCreatePolicy();
            }

            RenderStatus();
            _timer.Start();
            await LoadAccountChoicesAsync().ConfigureAwait(true);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _timer.Dispose();
            }

            base.Dispose(disposing);
        }

        // ---------- layout ----------

        private TabPage StatusPage()
        {
            Button refresh = Act("새로 고침", (_, _) =>
            {
                ReloadPolicy();
                RenderStatus();
            });
            _editControls.AddRange([_enforce, _emergency]);
            return Page(
                "상태",
                _statusList,
                _statusSummary,
                Row(_enforce),
                Row(_emergency),
                Row(refresh, _createPolicy),
                Heading("부원별 지금 상태"));
        }

        private TabPage MembersPage()
        {
            Button add = Act("부원 추가", (_, _) => AddMember());
            Button remove = Act("선택한 부원 빼기", (_, _) => RemoveSelected(_members, "부원", key => document => GuardPolicyEditor.RemoveMember(document, key)));
            _editControls.AddRange([_accountPicker, add, remove]);
            return Page(
                "부원",
                _members,
                Help("이 PC의 계정을 고르거나 계정 이름을 적고 '부원 추가'를 누르세요. 등록된 부원만 제한을 받아요. 관리자 계정은 부원이 될 수 없어요."),
                Row(Caption("계정"), _accountPicker, add, remove),
                Heading("등록된 부원"));
        }

        private TabPage GamesPage()
        {
            Button add = Act("실행 파일 골라서 추가…", async (_, _) => await AddGameAsync().ConfigureAwait(true));
            Button remove = Act("선택한 게임 빼기", (_, _) => RemoveSelected(_apps, "게임", key => document => GuardPolicyEditor.RemoveApplication(document, key)));
            _editControls.AddRange([_appName, add, remove]);
            return Page(
                "게임",
                _apps,
                Help("게임 실행 파일(.exe)을 고르면 게임 회사의 서명으로 등록해요. 파일 이름을 바꾸거나 게임이 업데이트돼도 계속 알아봐요."),
                Row(Caption("표시 이름"), _appName, add, remove),
                Heading("등록된 게임"));
        }

        private TabPage GrantsPage()
        {
            _grantDuration.Items.AddRange([new Choice("30", "30분"), new Choice("60", "1시간"), new Choice("120", "2시간"), new Choice(null, "오늘 끝까지")]);
            _grantDuration.SelectedIndex = 1;
            Button grant = Act("잠깐 허용", (_, _) => AddGrant());
            Button revoke = Act("선택한 허용 취소", (_, _) => RemoveSelected(_grants, "임시 허용", key => document => GuardPolicyEditor.RevokeGrants(document, key, DateTimeOffset.UtcNow)));
            Button revokeAll = Act("모두 취소", (_, _) => Apply(document => GuardPolicyEditor.RevokeGrants(document, null, DateTimeOffset.UtcNow), "모든 임시 허용을 취소했어요."));
            _editControls.AddRange([_grantMember, _grantApp, _grantDuration, grant, revoke, revokeAll]);
            return Page(
                "잠깐 허용",
                _grants,
                Help("제한 시간이라도 정한 시간 동안만 게임을 허용해요. 시간이 지나면 저절로 다시 제한돼요."),
                Row(Caption("누구"), _grantMember, Caption("게임"), _grantApp, Caption("얼마나"), _grantDuration, grant),
                Row(revoke, revokeAll),
                Heading("지금 켜져 있는 잠깐 허용"));
        }

        private TabPage SchedulePage()
        {
            Button save = Act("시간표 저장", (_, _) => SaveSchedule());
            Button clear = Act("시간표 지우기", (_, _) => Apply(GuardPolicyEditor.ClearWeekly, "주간 시간표를 지웠어요. 이제 쉬는 날·긴급 제한만 적용돼요."));
            Button addHoliday = Act("쉬는 날 추가", (_, _) => AddHoliday());
            Button removeHoliday = Act("선택한 날 지우기", (_, _) => RemoveSelected(_holidays, "날짜", key => document => GuardPolicyEditor.RemoveDateOverride(document, DateOnly.ParseExact(key, "yyyy-MM-dd", CultureInfo.InvariantCulture))));
            _editControls.AddRange(_days);
            _editControls.AddRange([_start, _end, _allDay, save, clear, _holidayDate, addHoliday, removeHoliday]);
            return Page(
                "시간표",
                _holidays,
                Heading("주간 시간표 — 고른 요일·시간에 등록된 게임을 제한해요"),
                Row(_days),
                Row(Caption("시작"), _start, Caption("끝"), _end, _allDay),
                Row(save, clear),
                Heading("쉬는 날 — 고른 날은 하루 종일 제한하지 않아요"),
                Row(_holidayDate, addHoliday, removeHoliday));
        }

        private TabPage LogPage()
        {
            _logPeriod.Items.AddRange([new Choice("1", "최근 1일"), new Choice("7", "최근 7일"), new Choice("30", "최근 30일")]);
            _logPeriod.SelectedIndex = 1;
            _logPeriod.SelectedIndexChanged += (_, _) => RenderLog();
            _ = _logView.Columns.Add("시각", 130);
            _ = _logView.Columns.Add("종류", 90);
            _ = _logView.Columns.Add("부원", 100);
            _ = _logView.Columns.Add("게임", 120);
            _ = _logView.Columns.Add("내용", 420);
            Button refresh = Act("새로 고침", (_, _) => RenderLog());
            Button export = Act("엑셀용 파일로 저장…", (_, _) => ExportLog());
            return Page(
                "기록",
                _logView,
                Help("막은 실행, 시험 운영 중 막았을 실행, 게임 종료, 설정 변경, 적용 문제가 기록돼요. 기록은 30일 동안 보관해요."),
                Row(_logPeriod, refresh, export, _logCount));
        }

        private static TabPage Page(string title, Control fill, params Control[] topToBottom)
        {
            TabPage page = new(title) { Padding = new Padding(10), UseVisualStyleBackColor = true };
            fill.Dock = DockStyle.Fill;
            page.Controls.Add(fill);
            // Docking lays out the last-added control first, so add the top controls bottom-up.
            for (int index = topToBottom.Length - 1; index >= 0; index--)
            {
                topToBottom[index].Dock = DockStyle.Top;
                page.Controls.Add(topToBottom[index]);
            }

            return page;
        }

        private static FlowLayoutPanel Row(params Control[] controls)
        {
            FlowLayoutPanel row = new() { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = true, Padding = new Padding(0, 2, 0, 2) };
            row.Controls.AddRange(controls);
            return row;
        }

        private static Label Caption(string text)
        {
            return new Label { Text = text, AutoSize = true, Margin = new Padding(3, 8, 3, 3) };
        }

        private static Label Heading(string text)
        {
            return new Label { Text = text, AutoSize = false, Height = 30, Font = HeadingFont, Padding = new Padding(0, 8, 0, 0) };
        }

        private static Label Help(string text)
        {
            return new Label { Text = text, AutoSize = false, Height = 46, ForeColor = SystemColors.GrayText, Padding = new Padding(2, 4, 2, 0) };
        }

        private static Button Act(string text, EventHandler onClick)
        {
            Button button = new() { Text = text, AutoSize = true, Padding = new Padding(6, 1, 6, 1) };
            button.Click += onClick;
            return button;
        }

        private static DateTimePicker TimePicker()
        {
            return new DateTimePicker { Format = DateTimePickerFormat.Custom, CustomFormat = "HH:mm", ShowUpDown = true, Width = 90 };
        }

        // ---------- loading and drawing ----------

        private void ReloadPolicy()
        {
            try
            {
                _document = GuardPolicyStore.ReadDocument(_policyPath);
            }
            catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
            {
                _document = null;
            }
            catch (Exception exception) when (exception is GuardConfigurationException or IOException)
            {
                _document = null;
                ShowError($"정책 파일을 읽지 못했어요. 서비스는 이전에 저장된 정책으로 계속 동작해요.\n\n{exception.Message}");
            }
            catch (UnauthorizedAccessException)
            {
                _document = null;
                ShowError("정책 파일을 열 권한이 없어요. 이 프로그램을 관리자 권한으로 실행해 주세요.");
            }

            RenderPolicy();
        }

        private void OfferToCreatePolicy()
        {
            DialogResult answer = MessageBox.Show(
                this,
                "아직 정책이 없어요. 지금 로그인한 계정을 관리자(Owner)로 해서 새로 만들까요?\n\n처음에는 '시험 운영' 모드라서 게임을 막지 않고 기록만 해요. 부원과 게임을 등록하고 며칠 지켜본 뒤 차단 모드로 바꾸세요.",
                Text,
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            if (answer != DialogResult.Yes)
            {
                return;
            }

            try
            {
                GuardPolicyDocument created = GuardPolicyEditor.CreateDefault(_userSid);
                _ = GuardPolicyStore.Write(_policyPath, created);
                RecordChange(created.PolicyVersion, "새 정책을 만들었어요.");
                Say("새 정책을 만들었어요. 기본값: 매일 09:00~18:00 제한, 시험 운영 모드.");
            }
            catch (Exception exception) when (exception is GuardConfigurationException or IOException or UnauthorizedAccessException)
            {
                ShowError($"정책을 만들지 못했어요: {exception.Message}");
            }

            ReloadPolicy();
        }

        private void RenderPolicy()
        {
            _rendering = true;
            try
            {
                GuardPolicyDocument? document = _document;
                _header.ForeColor = CanEdit ? SystemColors.ControlText : Color.Firebrick;
                bool missing = !File.Exists(_policyPath) && !File.Exists(GuardPolicyStore.BackupPath(_policyPath));
                _createPolicy.Visible = document is null && missing;
                _header.Text = document is null
                    ? missing ? "정책이 없어요. 상태 탭의 '정책 새로 만들기'를 누르세요." : "정책 파일을 읽지 못했어요. 명령어 도구(guard policy)로 확인해 주세요."
                    : !CanEdit
                    ? $"이 계정은 관리자(Owner)가 아니라서 볼 수만 있어요. (설정 {document.PolicyVersion}번)"
                    : $"설정 {document.PolicyVersion}번 · {(document.AuditOnly ? "시험 운영(기록만)" : "차단")} 모드{(document.EmergencyRestriction ? " · 긴급 제한 켜짐" : string.Empty)}";
                foreach (Control control in _editControls)
                {
                    control.Enabled = CanEdit;
                }

                if (document is null)
                {
                    _members.Items.Clear();
                    _apps.Items.Clear();
                    _grants.Items.Clear();
                    _holidays.Items.Clear();
                    return;
                }

                TimeZoneInfo zone = GuardPolicyDocumentReader.ToConfiguration(document).Policy.TimeZone;
                DateTimeOffset now = DateTimeOffset.UtcNow;
                IReadOnlyList<GuardMemberDocument> members = document.Members ?? [];
                IReadOnlyList<GuardApplicationDocument> apps = document.Applications ?? [];

                _enforce.Checked = !document.AuditOnly;
                _emergency.Checked = document.EmergencyRestriction;

                Refill(_members, members.Select(member => new Choice(member.Sid, member.Name ?? member.Sid ?? "?")));
                Refill(_apps, apps.Select(app => new Choice(
                    app.AppId,
                    $"{app.DisplayName} ({string.Join(", ", (app.PublisherIdentities ?? []).Select(identity => identity.Binary))})")));
                Refill(_grantMember, [new Choice(null, "모든 부원"), .. members.Select(member => new Choice(member.Sid, member.Name ?? "?"))]);
                Refill(_grantApp, [new Choice(null, "모든 게임"), .. apps.Select(app => new Choice(app.AppId, app.DisplayName ?? app.AppId ?? "?"))]);
                Refill(_grants, (document.TemporaryGrants ?? [])
                    .Where(grant => !grant.Revoked && grant.ExpiresAtUtc > now)
                    .OrderBy(grant => grant.ExpiresAtUtc)
                    .Select(grant => new Choice(grant.Id, $"{MemberName(document, grant.MemberSid)} · {AppName(document, grant.AppId)} · {Clock(grant.ExpiresAtUtc, now, zone)}까지")));
                Refill(_holidays, (document.DateOverrides ?? [])
                    .OrderBy(rule => rule.Date, StringComparer.Ordinal)
                    .Select(rule => new Choice(rule.Date, DescribeDate(rule))));

                IReadOnlyList<GuardWeeklyRuleDocument> rules = document.WeeklyRules ?? [];
                GuardWeeklyRuleDocument? weekly = rules.Count > 0 ? rules[0] : null;
                for (int index = 0; index < Week.Length; index++)
                {
                    _days[index].Checked = weekly?.Days?.Contains(Week[index]) == true;
                }

                _allDay.Checked = weekly?.AllDay == true;
                _start.Value = TimeOn(weekly?.Start ?? "09:00");
                _end.Value = TimeOn(weekly?.End ?? "18:00");
                _start.Enabled = _end.Enabled = !_allDay.Checked && CanEdit;
            }
            finally
            {
                _rendering = false;
            }
        }

        private void RenderStatus()
        {
            GuardStatusSnapshot? snapshot = GuardStatusFile.TryRead(_statusPath);
            _statusList.Items.Clear();
            if (snapshot is null)
            {
                _statusSummary.Text = "서비스 상태를 아직 읽을 수 없어요. 서비스가 설치되어 켜져 있는지 확인하세요.";
                return;
            }

            TimeZoneInfo zone = Zone(snapshot.TimeZoneId);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            List<string> lines = [$"서비스 상태: {snapshot.Health}{(snapshot.HealthDetail is { Length: > 0 } detail ? $" — {detail}" : string.Empty)}"];
            lines.Add(_document is not null && snapshot.PolicyVersion < _document.PolicyVersion
                ? $"방금 저장한 설정 {_document.PolicyVersion}번을 서비스가 반영하는 중이에요… (지금 적용: {snapshot.PolicyVersion}번)"
                : $"서비스가 설정 {snapshot.PolicyVersion}번을 적용하고 있어요. 마지막 확인 {Clock(snapshot.UpdatedUtc, now, zone)}");
            if (now - snapshot.UpdatedUtc > StaleAfter)
            {
                lines.Add("주의: 서비스가 3분 넘게 소식이 없어요. 서비스가 멈췄을 수 있어요.");
            }

            if (snapshot.NextChangeUtc is { } next)
            {
                lines.Add($"다음에 상태가 바뀌는 시각: {Clock(next, now, zone)}");
            }

            _statusSummary.Text = string.Join(Environment.NewLine, lines);
            foreach (GuardMemberStatus member in snapshot.Members)
            {
                _ = _statusList.Items.Add($"■ {member.Name}");
                foreach (GuardAppStatus app in member.Apps)
                {
                    _ = _statusList.Items.Add($"      {GuardStatusMessages.Describe(app, now, zone)}");
                }
            }

            if (snapshot.Members.Count == 0)
            {
                _ = _statusList.Items.Add("등록된 부원이 없어요. '부원' 탭에서 추가하세요.");
            }
        }

        private void OnTimer()
        {
            // Pick up edits made from the command line, then refresh the service status.
            long? shown = _document?.PolicyVersion;
            try
            {
                if (File.Exists(_policyPath) && GuardPolicyStore.ReadDocument(_policyPath).PolicyVersion != shown)
                {
                    ReloadPolicy();
                }
            }
            catch (Exception exception) when (exception is GuardConfigurationException or IOException or UnauthorizedAccessException)
            {
                // A half-written or locked file is retried on the next tick.
            }

            RenderStatus();
        }

        private async Task LoadAccountChoicesAsync()
        {
            IReadOnlyList<LocalAccount> accounts;
            try
            {
                accounts = await _gateway.ListLocalAccountsAsync(CancellationToken.None).ConfigureAwait(true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or TimeoutException or IOException or FormatException)
            {
                // Typing an account name still works without the list.
                return;
            }

            HashSet<string> members = [.. (_document?.Members ?? []).Select(member => member.Sid ?? string.Empty)];
            _accountPicker.Items.Clear();
            foreach (LocalAccount account in accounts.Where(account => account.Sid != _document?.OwnerSid && !members.Contains(account.Sid) && !IsBuiltIn(account.Sid)).OrderBy(account => account.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                _ = _accountPicker.Items.Add(new AccountChoice(account));
            }
        }

        // ---------- edits ----------

        /// <summary>Re-reads the file, checks the Owner, applies <paramref name="edit"/>, saves, and redraws.</summary>
        private void Apply(Func<GuardPolicyDocument, GuardPolicyDocument> edit, string done)
        {
            try
            {
                GuardPolicyDocument current = GuardPolicyStore.ReadDocument(_policyPath);
                if (current.OwnerSid != _userSid)
                {
                    throw new GuardConfigurationException("정책은 등록된 관리자(Owner) 계정만 바꿀 수 있어요.");
                }

                GuardPolicyDocument updated = edit(current);
                _ = GuardPolicyStore.Write(_policyPath, updated);
                RecordChange(updated.PolicyVersion, done);
                Say($"{done} 설정 {updated.PolicyVersion}번으로 저장했어요. 서비스가 몇 초 안에 반영해요.");
            }
            catch (GuardConfigurationException exception)
            {
                ShowError(exception.Message);
            }
            catch (UnauthorizedAccessException)
            {
                ShowError("권한이 없어요. 이 프로그램을 관리자 권한으로 실행해 주세요.");
            }
            catch (IOException exception)
            {
                ShowError($"정책 파일을 읽거나 쓰지 못했어요: {exception.Message}");
            }

            // Redraw from disk either way, so a refused change does not stay half-shown (for example a ticked box).
            ReloadPolicy();
            RenderStatus();
        }

        private void RemoveSelected(ListBox list, string what, Func<string, Func<GuardPolicyDocument, GuardPolicyDocument>> edit)
        {
            if (list.SelectedItem is not Choice { Key: { } key } choice)
            {
                ShowError($"목록에서 뺄 {what}을(를) 먼저 골라 주세요.");
                return;
            }

            Apply(edit(key), $"{what} '{choice.Text}'을(를) 뺐어요.");
        }

        private void OnEnforceChanged()
        {
            if (_rendering)
            {
                return;
            }

            if (_enforce.Checked && MessageBox.Show(
                this,
                "차단 모드로 바꾸면 제한 시간에 등록된 게임이 실제로 막히고, 켜져 있던 게임은 15초 경고 뒤에 꺼져요.\n바꿀까요?",
                Text,
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning) != DialogResult.Yes)
            {
                RenderPolicy();
                return;
            }

            bool enforce = _enforce.Checked;
            Apply(document => GuardPolicyEditor.SetAuditOnly(document, !enforce), enforce ? "차단 모드로 바꿨어요." : "시험 운영 모드로 바꿨어요. 이제 막지 않고 기록만 해요.");
        }

        private void OnEmergencyChanged()
        {
            if (_rendering)
            {
                return;
            }

            bool on = _emergency.Checked;
            Apply(document => GuardPolicyEditor.SetEmergency(document, on), on ? "긴급 제한을 켰어요. 시간표·잠깐 허용과 상관없이 게임이 막혀요." : "긴급 제한을 껐어요.");
        }

        private void AddMember()
        {
            string typed = _accountPicker.Text.Trim();
            if (typed.Length == 0)
            {
                ShowError("부원으로 등록할 계정을 고르거나 적어 주세요.");
                return;
            }

            AccountChoice? picked = _accountPicker.SelectedItem is AccountChoice choice && choice.ToString() == _accountPicker.Text ? choice : null;
            Apply(
                document =>
                {
                    (string name, string sid) = picked is not null ? (picked.Account.Name, picked.Account.Sid) : WindowsAccounts.Resolve(typed);
                    return GuardPolicyEditor.AddMember(document, name, sid);
                },
                $"부원 '{picked?.Account.Name ?? typed}'을(를) 등록했어요.");
            _accountPicker.Text = string.Empty;
            _ = LoadAccountChoicesAsync();
        }

        private async Task AddGameAsync()
        {
            using OpenFileDialog dialog = new()
            {
                Title = "제한할 게임의 실행 파일을 고르세요",
                Filter = "실행 파일 (*.exe)|*.exe",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            };
            if (dialog.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            NativeFileIdentity identity;
            UseWaitCursor = true;
            Say("실행 파일의 서명을 확인하는 중이에요…");
            try
            {
                identity = await _gateway.ReadFileIdentityAsync(dialog.FileName, CancellationToken.None).ConfigureAwait(true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or TimeoutException or FormatException or IOException)
            {
                ShowError($"이 파일은 등록할 수 없어요.\n\n{exception.Message}");
                return;
            }
            finally
            {
                UseWaitCursor = false;
            }

            string appId = Path.GetFileNameWithoutExtension(identity.Binary).ToLowerInvariant();
            string displayName = _appName.Text.Trim() is { Length: > 0 } typed ? typed : FriendlyName(identity, dialog.FileName);
            Apply(
                document => GuardPolicyEditor.AddApplication(document, appId, displayName, identity),
                $"게임 '{displayName}'을(를) 등록했어요 ({identity.Binary}). 모든 버전이 대상이에요.");
            _appName.Text = string.Empty;
        }

        private void AddGrant()
        {
            string? memberSid = (_grantMember.SelectedItem as Choice)?.Key;
            string? appId = (_grantApp.SelectedItem as Choice)?.Key;
            string? minutes = (_grantDuration.SelectedItem as Choice)?.Key;
            string who = _grantMember.Text;
            string game = _grantApp.Text;
            Apply(
                document =>
                {
                    DateTimeOffset now = DateTimeOffset.UtcNow;
                    TimeZoneInfo zone = GuardPolicyDocumentReader.ToConfiguration(document).Policy.TimeZone;
                    DateTimeOffset expires = minutes is null
                        ? GuardPolicyEditor.EndOfLocalDay(now, zone)
                        : now.AddMinutes(int.Parse(minutes, CultureInfo.InvariantCulture));
                    return GuardPolicyEditor.AddGrant(document, memberSid, appId, now, expires);
                },
                $"{who} · {game}: {_grantDuration.Text} 동안 허용했어요.");
        }

        private void SaveSchedule()
        {
            DayOfWeek[] days = [.. Week.Where((_, index) => _days[index].Checked)];
            if (days.Length == 0)
            {
                ShowError("제한할 요일을 하나 이상 골라 주세요. 시간표를 없애려면 '시간표 지우기'를 누르세요.");
                return;
            }

            string start = _start.Value.ToString("HH:mm", CultureInfo.InvariantCulture);
            string end = _end.Value.ToString("HH:mm", CultureInfo.InvariantCulture);
            bool allDay = _allDay.Checked;
            string dayText = string.Join(",", days.Select(KoreanDay));
            Apply(
                document => GuardPolicyEditor.SetWeekly(document, days, start, end, allDay),
                allDay ? $"시간표: {dayText} 하루 종일 제한." : $"시간표: {dayText} {start}~{end} 제한.");
        }

        private void AddHoliday()
        {
            DateOnly date = DateOnly.FromDateTime(_holidayDate.Value);
            Apply(
                document => GuardPolicyEditor.SetDateOverride(document, date, []),
                $"{date.ToString("M월 d일", CultureInfo.GetCultureInfo("ko-KR"))}은(는) 하루 종일 제한하지 않아요.");
        }

        // ---------- activity record ----------

        private void RenderLog()
        {
            int days = _logPeriod.SelectedItem is Choice { Key: { } key } ? int.Parse(key, CultureInfo.InvariantCulture) : 7;
            IReadOnlyList<GuardAuditEntry> entries;
            try
            {
                entries = ReadLog(days);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Say($"기록을 읽지 못했어요: {exception.Message}");
                return;
            }

            TimeZoneInfo zone = Zone(_document?.TimeZoneId);
            _logView.BeginUpdate();
            _logView.Items.Clear();
            foreach (GuardAuditEntry entry in entries.Reverse())
            {
                _ = _logView.Items.Add(new ListViewItem(
                [
                    TimeZoneInfo.ConvertTime(entry.AtUtc, zone).ToString("MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                    GuardAuditLog.Label(entry.Kind),
                    entry.Member ?? string.Empty,
                    entry.App ?? string.Empty,
                    entry.Detail,
                ]));
            }

            _logView.EndUpdate();
            _logCount.Text = $"{entries.Count}건 (최신이 위)";
        }

        private void ExportLog()
        {
            int days = _logPeriod.SelectedItem is Choice { Key: { } key } ? int.Parse(key, CultureInfo.InvariantCulture) : 30;
            using SaveFileDialog dialog = new()
            {
                Title = "기록을 저장할 곳을 고르세요",
                Filter = "엑셀에서 열 수 있는 파일 (*.csv)|*.csv",
                FileName = $"COMS-PC-Guard-기록-{DateTime.Now:yyyyMMdd}.csv",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            };
            if (dialog.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            try
            {
                IReadOnlyList<GuardAuditEntry> entries = ReadLog(days);
                GuardAuditLog.WriteCsv(dialog.FileName, entries, Zone(_document?.TimeZoneId));
                Say($"기록 {entries.Count}건을 저장했어요: {dialog.FileName}");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                ShowError($"파일을 저장하지 못했어요: {exception.Message}");
            }
        }

        private IReadOnlyList<GuardAuditEntry> ReadLog(int days)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            return _audit.Read(now.AddDays(-days), now.AddSeconds(1));
        }

        /// <summary>Best effort: a missing record line must never make a saved change look failed.</summary>
        private void RecordChange(long policyVersion, string text)
        {
            try
            {
                _audit.Append(new GuardAuditEntry(DateTimeOffset.UtcNow, GuardAuditKind.PolicyChanged, null, null, $"{text} (설정 {policyVersion}번, {Environment.UserName}, 관리 화면)"));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Say($"설정은 저장했지만 기록을 남기지 못했어요: {exception.Message}");
            }
        }

        // ---------- helpers ----------

        private void Say(string text)
        {
            _message.Text = $"{DateTime.Now:HH:mm:ss}  {text}";
        }

        private void ShowError(string text)
        {
            Say(text.Split('\n')[0]);
            _ = MessageBox.Show(this, text, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private static void Refill(ListBox list, IEnumerable<Choice> items)
        {
            string? selected = (list.SelectedItem as Choice)?.Key;
            list.BeginUpdate();
            list.Items.Clear();
            foreach (Choice item in items)
            {
                int index = list.Items.Add(item);
                if (selected is not null && item.Key == selected)
                {
                    list.SelectedIndex = index;
                }
            }

            list.EndUpdate();
        }

        private static void Refill(ComboBox combo, IEnumerable<Choice> items)
        {
            string? selected = (combo.SelectedItem as Choice)?.Key;
            combo.BeginUpdate();
            combo.Items.Clear();
            int keep = 0;
            foreach (Choice item in items)
            {
                int index = combo.Items.Add(item);
                if (item.Key == selected)
                {
                    keep = index;
                }
            }

            combo.SelectedIndex = combo.Items.Count > 0 ? keep : -1;
            combo.EndUpdate();
        }

        private static string MemberName(GuardPolicyDocument document, string? sid)
        {
            return sid is null ? "모든 부원" : (document.Members ?? []).FirstOrDefault(member => member.Sid == sid)?.Name ?? sid;
        }

        private static string AppName(GuardPolicyDocument document, string? appId)
        {
            return appId is null ? "모든 게임" : (document.Applications ?? []).FirstOrDefault(app => app.AppId == appId)?.DisplayName ?? appId;
        }

        private static string DescribeDate(GuardDateOverrideDocument rule)
        {
            string label = DateOnly.TryParseExact(rule.Date, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date)
                ? date.ToString("yyyy년 M월 d일 (ddd)", CultureInfo.GetCultureInfo("ko-KR"))
                : rule.Date ?? "?";
            IReadOnlyList<GuardTimeWindowDocument> windows = rule.Windows ?? [];
            return windows.Count == 0
                ? $"{label}: 하루 종일 제한 없음"
                : $"{label}: {string.Join(", ", windows.Select(window => $"{window.Start}~{window.End}"))}에만 제한";
        }

        private static string FriendlyName(NativeFileIdentity identity, string path)
        {
            string? product = System.Diagnostics.FileVersionInfo.GetVersionInfo(path).ProductName;
            return product is { Length: > 0 } ? product.Trim() : Path.GetFileNameWithoutExtension(identity.Binary);
        }

        private static string Clock(DateTimeOffset at, DateTimeOffset nowUtc, TimeZoneInfo zone)
        {
            DateTimeOffset local = TimeZoneInfo.ConvertTime(at, zone);
            return local.Date == TimeZoneInfo.ConvertTime(nowUtc, zone).Date
                ? local.ToString("HH:mm", CultureInfo.InvariantCulture)
                : local.ToString("M월 d일 HH:mm", CultureInfo.GetCultureInfo("ko-KR"));
        }

        private static DateTime TimeOn(string clock)
        {
            return TimeOnly.TryParseExact(clock, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out TimeOnly time)
                ? DateTime.Today.Add(time.ToTimeSpan())
                : DateTime.Today.AddHours(9);
        }

        private static TimeZoneInfo Zone(string? id)
        {
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(id ?? GuardPolicyDocumentReader.DefaultTimeZoneId);
            }
            catch (TimeZoneNotFoundException)
            {
                return TimeZoneInfo.Local;
            }
        }

        private static bool IsBuiltIn(string sid)
        {
            // Administrator, Guest, DefaultAccount and WDAGUtilityAccount are never club members.
            return sid.EndsWith("-500", StringComparison.Ordinal) || sid.EndsWith("-501", StringComparison.Ordinal)
                || sid.EndsWith("-503", StringComparison.Ordinal) || sid.EndsWith("-504", StringComparison.Ordinal);
        }

        private static string KoreanDay(DayOfWeek day)
        {
            return day switch
            {
                DayOfWeek.Monday => "월",
                DayOfWeek.Tuesday => "화",
                DayOfWeek.Wednesday => "수",
                DayOfWeek.Thursday => "목",
                DayOfWeek.Friday => "금",
                DayOfWeek.Saturday => "토",
                _ => "일",
            };
        }
    }
}
