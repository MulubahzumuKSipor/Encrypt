using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Drawing2D;

namespace SecureMessageApp
{
    public class SecureMessageForm : Form
    {
        private Panel headerPanel;
        private Panel mainPanel;
        private RoundedTextBox txtMessage;
        private RoundedTextBox txtPassword;
        private ModernButton btnEncrypt;
        private ModernButton btnDecrypt;
        private ModernButton btnCopy;
        private ModernButton btnClear;
        private Label lblStatus;
        private Label lblPasswordStrength;
        private CheckBox chkShowPassword;
        private ProgressBar strengthBar;
        private System.Windows.Forms.Timer clipboardTimer;

        public SecureMessageForm()
        {
            SetupUI();
        }

        private void SetupUI()
        {
            this.Text = "SecureMessage Pro";
            this.Size = new Size(800, 700);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.None;
            this.BackColor = Color.FromArgb(240, 242, 245);

            Panel shadowPanel = new Panel
            {
                Location = new Point(10, 10),
                Size = new Size(780, 680),
                BackColor = Color.White
            };
            shadowPanel.Paint += (s, e) => {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                using (var path = GetRoundedRect(shadowPanel.ClientRectangle, 20))
                {
                    shadowPanel.Region = new Region(path);
                }
            };

            headerPanel = new Panel
            {
                Location = new Point(0, 0),
                Size = new Size(780, 120),
                BackColor = Color.FromArgb(67, 97, 238)
            };
            headerPanel.Paint += (s, e) => {
                var rect = headerPanel.ClientRectangle;
                using (var brush = new LinearGradientBrush(
                    rect,
                    Color.FromArgb(67, 97, 238),
                    Color.FromArgb(115, 103, 240),
                    45f))
                {
                    e.Graphics.FillRectangle(brush, rect);
                }
            };

            Label lblTitle = new Label
            {
                Text = "🔐 SecureMessage Pro",
                Font = new Font("Segoe UI", 24, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(30, 25),
                AutoSize = true
            };

            Label lblSubtitle = new Label
            {
                Text = "Military-Grade Encryption • AES-256-GCM • Zero-Knowledge Security",
                Font = new Font("Segoe UI", 9, FontStyle.Regular),
                ForeColor = Color.FromArgb(220, 220, 255),
                Location = new Point(35, 65),
                AutoSize = true
            };

            Button btnClose = new Button
            {
                Text = "✕",
                Location = new Point(730, 10),
                Size = new Size(40, 40),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Arial", 16, FontStyle.Bold),
                ForeColor = Color.White,
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.FlatAppearance.MouseOverBackColor = Color.FromArgb(220, 53, 69);
            btnClose.Click += (s, e) => Application.Exit();

            Button btnMinimize = new Button
            {
                Text = "─",
                Location = new Point(685, 10),
                Size = new Size(40, 40),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Arial", 16, FontStyle.Bold),
                ForeColor = Color.White,
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand
            };
            btnMinimize.FlatAppearance.BorderSize = 0;
            btnMinimize.FlatAppearance.MouseOverBackColor = Color.FromArgb(100, 100, 255);
            btnMinimize.Click += (s, e) => this.WindowState = FormWindowState.Minimized;

            headerPanel.Controls.Add(lblTitle);
            headerPanel.Controls.Add(lblSubtitle);
            headerPanel.Controls.Add(btnClose);
            headerPanel.Controls.Add(btnMinimize);

            mainPanel = new Panel
            {
                Location = new Point(0, 120),
                Size = new Size(780, 560),
                BackColor = Color.White
            };

            Label lblMessageTitle = new Label
            {
                Text = "📝 Your Message",
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                ForeColor = Color.FromArgb(50, 50, 70),
                Location = new Point(40, 20),
                AutoSize = true
            };

            txtMessage = new RoundedTextBox
            {
                Location = new Point(40, 50),
                Size = new Size(700, 150),
                Font = new Font("Consolas", 11),
                BorderColor = Color.FromArgb(200, 200, 220),
                Multiline = true
            };

            Label lblPasswordTitle = new Label
            {
                Text = "🔑 Encryption Password",
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                ForeColor = Color.FromArgb(50, 50, 70),
                Location = new Point(40, 220),
                AutoSize = true
            };

            txtPassword = new RoundedTextBox
            {
                Location = new Point(40, 250),
                Size = new Size(500, 45),
                Font = new Font("Segoe UI", 12),
                BorderColor = Color.FromArgb(200, 200, 220),
                UseSystemPasswordChar = true
            };
            txtPassword.TextChanged += TxtPassword_TextChanged;

            chkShowPassword = new CheckBox
            {
                Text = "Show",
                Location = new Point(555, 258),
                Size = new Size(80, 30),
                Font = new Font("Segoe UI", 10),
                ForeColor = Color.FromArgb(100, 100, 120),
                Cursor = Cursors.Hand
            };
            chkShowPassword.CheckedChanged += (s, e) => {
                txtPassword.UseSystemPasswordChar = !chkShowPassword.Checked;
            };

            lblPasswordStrength = new Label
            {
                Location = new Point(645, 258),
                Size = new Size(95, 30),
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleRight
            };

            strengthBar = new ProgressBar
            {
                Location = new Point(40, 300),
                Size = new Size(700, 8),
                Style = ProgressBarStyle.Continuous,
                Minimum = 0,
                Maximum = 100
            };

            Label lblMinPassword = new Label
            {
                Text = "Minimum 12 characters • Mix upper/lower case • Include numbers & symbols",
                Font = new Font("Segoe UI", 8, FontStyle.Italic),
                ForeColor = Color.Gray,
                Location = new Point(42, 313),
                AutoSize = true
            };

            btnEncrypt = new ModernButton
            {
                Text = "🔒 ENCRYPT",
                Location = new Point(40, 360),
                Size = new Size(160, 55),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ButtonColor = Color.FromArgb(40, 167, 69),
                HoverColor = Color.FromArgb(33, 140, 58)
            };
            btnEncrypt.Click += BtnEncrypt_Click;

            btnDecrypt = new ModernButton
            {
                Text = "🔓 DECRYPT",
                Location = new Point(220, 360),
                Size = new Size(160, 55),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ButtonColor = Color.FromArgb(0, 123, 255),
                HoverColor = Color.FromArgb(0, 100, 220)
            };
            btnDecrypt.Click += BtnDecrypt_Click;

            btnCopy = new ModernButton
            {
                Text = "📋 COPY",
                Location = new Point(400, 360),
                Size = new Size(160, 55),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ButtonColor = Color.FromArgb(255, 193, 7),
                HoverColor = Color.FromArgb(230, 170, 0),
                ForeColor = Color.FromArgb(50, 50, 50)
            };
            btnCopy.Click += BtnCopy_Click;

            btnClear = new ModernButton
            {
                Text = "🗑 CLEAR",
                Location = new Point(580, 360),
                Size = new Size(160, 55),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ButtonColor = Color.FromArgb(220, 53, 69),
                HoverColor = Color.FromArgb(200, 35, 51)
            };
            btnClear.Click += BtnClear_Click;

            Panel statusPanel = new Panel
            {
                Location = new Point(30, 440),
                Size = new Size(720, 90),
                BackColor = Color.FromArgb(248, 249, 250)
            };
            statusPanel.Paint += (s, e) => {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                using (var path = GetRoundedRect(statusPanel.ClientRectangle, 10))
                {
                    statusPanel.Region = new Region(path);
                }
            };

            lblStatus = new Label
            {
                Location = new Point(20, 15),
                Size = new Size(680, 60),
                Font = new Font("Segoe UI", 10),
                ForeColor = Color.FromArgb(100, 100, 120),
                TextAlign = ContentAlignment.TopLeft
            };

            statusPanel.Controls.Add(lblStatus);

            mainPanel.Controls.Add(lblMessageTitle);
            mainPanel.Controls.Add(txtMessage);
            mainPanel.Controls.Add(lblPasswordTitle);
            mainPanel.Controls.Add(txtPassword);
            mainPanel.Controls.Add(chkShowPassword);
            mainPanel.Controls.Add(lblPasswordStrength);
            mainPanel.Controls.Add(strengthBar);
            mainPanel.Controls.Add(lblMinPassword);
            mainPanel.Controls.Add(btnEncrypt);
            mainPanel.Controls.Add(btnDecrypt);
            mainPanel.Controls.Add(btnCopy);
            mainPanel.Controls.Add(btnClear);
            mainPanel.Controls.Add(statusPanel);

            shadowPanel.Controls.Add(headerPanel);
            shadowPanel.Controls.Add(mainPanel);
            this.Controls.Add(shadowPanel);

            clipboardTimer = new System.Windows.Forms.Timer();
            clipboardTimer.Interval = 30000;
            clipboardTimer.Tick += (s, e) => {
                Clipboard.Clear();
                clipboardTimer.Stop();
                ShowStatus("🔒 Clipboard cleared automatically for security", Color.Gray);
            };

            bool isDragging = false;
            Point dragStart = Point.Empty;
            headerPanel.MouseDown += (s, e) => { isDragging = true; dragStart = e.Location; };
            headerPanel.MouseMove += (s, e) => {
                if (isDragging) {
                    Point p = PointToScreen(e.Location);
                    Location = new Point(p.X - dragStart.X, p.Y - dragStart.Y);
                }
            };
            headerPanel.MouseUp += (s, e) => { isDragging = false; };
        }

        private GraphicsPath GetRoundedRect(Rectangle bounds, int radius)
        {
            int diameter = radius * 2;
            GraphicsPath path = new GraphicsPath();
            path.AddArc(bounds.X, bounds.Y, diameter, diameter, 180, 90);
            path.AddArc(bounds.Right - diameter, bounds.Y, diameter, diameter, 270, 90);
            path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0, 90);
            path.AddArc(bounds.X, bounds.Bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
            return path;
        }

        private void TxtPassword_TextChanged(object sender, EventArgs e)
        {
            string password = txtPassword.Text;
            var strength = CalculatePasswordStrength(password);

            lblPasswordStrength.Text = strength.Label;
            lblPasswordStrength.ForeColor = strength.Color;
            strengthBar.Value = strength.Score;
            strengthBar.ForeColor = strength.Color;
        }

        private (string Label, Color Color, int Score) CalculatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return ("", Color.Gray, 0);

            int score = 0;
            int maxScore = 6;

            if (password.Length >= 12) score++;
            if (password.Length >= 16) score++;
            if (password.Any(char.IsUpper)) score++;
            if (password.Any(char.IsLower)) score++;
            if (password.Any(char.IsDigit)) score++;
            if (password.Any(ch => !char.IsLetterOrDigit(ch))) score++;

            int percentage = (int)((score / (float)maxScore) * 100);

            return score switch
            {
                <= 2 => ("WEAK", Color.FromArgb(220, 53, 69), percentage),
                3 => ("FAIR", Color.FromArgb(255, 193, 7), percentage),
                4 => ("GOOD", Color.FromArgb(40, 167, 69), percentage),
                5 => ("STRONG", Color.FromArgb(0, 123, 255), percentage),
                _ => ("EXCELLENT", Color.FromArgb(115, 103, 240), percentage)
            };
        }

        private void BtnEncrypt_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtMessage.Text))
            {
                ShowStatus("⚠ Please enter a message to encrypt", Color.FromArgb(255, 193, 7));
                return;
            }

            if (string.IsNullOrWhiteSpace(txtPassword.Text))
            {
                ShowStatus("⚠ Please enter a password", Color.FromArgb(255, 193, 7));
                return;
            }

            if (txtPassword.Text.Length < 12)
            {
                ShowStatus("⚠ Password must be at least 12 characters", Color.FromArgb(220, 53, 69));
                MessageBox.Show(
                    "For your security, please use a strong password:\n\n" +
                    "✓ At least 12 characters (16+ recommended)\n" +
                    "✓ Mix of uppercase and lowercase letters\n" +
                    "✓ Include numbers and special characters\n" +
                    "✓ Avoid common words or patterns",
                    "Weak Password Detected",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
                return;
            }

            try
            {
                btnEncrypt.Enabled = false;
                btnEncrypt.Text = "⏳ ENCRYPTING...";
                Application.DoEvents();

                string encrypted = SecureEncrypt(txtMessage.Text, txtPassword.Text);
                txtMessage.Text = encrypted;

                ShowStatus("✅ Message encrypted successfully with AES-256-GCM!\n" +
                          "Your message is now secured with military-grade encryption. Share it safely.",
                          Color.FromArgb(40, 167, 69));
            }
            catch (Exception ex)
            {
                ShowStatus("❌ Encryption failed: " + ex.Message, Color.FromArgb(220, 53, 69));
            }
            finally
            {
                btnEncrypt.Enabled = true;
                btnEncrypt.Text = "🔒 ENCRYPT";
            }
        }

        private void BtnDecrypt_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtMessage.Text))
            {
                ShowStatus("⚠ Please enter encrypted text to decrypt", Color.FromArgb(255, 193, 7));
                return;
            }

            if (string.IsNullOrWhiteSpace(txtPassword.Text))
            {
                ShowStatus("⚠ Please enter the decryption password", Color.FromArgb(255, 193, 7));
                return;
            }

            try
            {
                btnDecrypt.Enabled = false;
                btnDecrypt.Text = "⏳ DECRYPTING...";
                Application.DoEvents();

                string decrypted = SecureDecrypt(txtMessage.Text, txtPassword.Text);
                txtMessage.Text = decrypted;

                ShowStatus("✅ Message decrypted and authenticated successfully!\n" +
                          "The message integrity has been verified. No tampering detected.",
                          Color.FromArgb(40, 167, 69));
            }
            catch (CryptographicException)
            {
                ShowStatus("❌ AUTHENTICATION FAILED! Wrong password or tampered message.",
                          Color.FromArgb(220, 53, 69));
                MessageBox.Show(
                    "⚠ Decryption Failed!\n\n" +
                    "This could mean:\n\n" +
                    "• Incorrect password\n" +
                    "• Message was modified or corrupted\n" +
                    "• Incomplete encrypted text\n\n" +
                    "Please verify your password and ensure the encrypted text is complete.",
                    "Authentication Failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
            catch (FormatException)
            {
                ShowStatus("❌ Invalid encrypted text format", Color.FromArgb(220, 53, 69));
            }
            catch (Exception ex)
            {
                ShowStatus("❌ Decryption error: " + ex.Message, Color.FromArgb(220, 53, 69));
            }
            finally
            {
                btnDecrypt.Enabled = true;
                btnDecrypt.Text = "🔓 DECRYPT";
            }
        }

        private void BtnCopy_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(txtMessage.Text))
            {
                Clipboard.SetText(txtMessage.Text);
                ShowStatus("✅ Copied to clipboard!\n" +
                          "⏱ Auto-clear in 30 seconds for security.",
                          Color.FromArgb(40, 167, 69));

                clipboardTimer.Stop();
                clipboardTimer.Start();
            }
        }

        private void BtnClear_Click(object sender, EventArgs e)
        {
            txtMessage.Text = "";
            txtPassword.Text = "";
            lblStatus.Text = "";
            lblPasswordStrength.Text = "";
            strengthBar.Value = 0;
            Clipboard.Clear();
            clipboardTimer.Stop();
            ShowStatus("🗑 All data cleared", Color.Gray);
        }

        private void ShowStatus(string message, Color color)
        {
            lblStatus.Text = message;
            lblStatus.ForeColor = color;
        }

        private string SecureEncrypt(string plainText, string password)
        {
            byte[] salt = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(salt);

            byte[] key = DeriveKey(password, salt);
            byte[] nonce = new byte[12];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(nonce);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherBytes = new byte[plainBytes.Length];
            byte[] tag = new byte[16];

            using (var aesGcm = new AesGcm(key, 16))
                aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

            Array.Clear(key, 0, key.Length);

            using (var ms = new MemoryStream())
            {
                ms.Write(salt, 0, salt.Length);
                ms.Write(nonce, 0, nonce.Length);
                ms.Write(tag, 0, tag.Length);
                ms.Write(cipherBytes, 0, cipherBytes.Length);
                return Convert.ToBase64String(ms.ToArray());
            }
        }

        private string SecureDecrypt(string encryptedText, string password)
        {
            byte[] fullData = Convert.FromBase64String(encryptedText);
            if (fullData.Length < 60)
                throw new CryptographicException("Invalid encrypted data");

            byte[] salt = new byte[32];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] cipherBytes = new byte[fullData.Length - 60];

            Array.Copy(fullData, 0, salt, 0, 32);
            Array.Copy(fullData, 32, nonce, 0, 12);
            Array.Copy(fullData, 44, tag, 0, 16);
            Array.Copy(fullData, 60, cipherBytes, 0, cipherBytes.Length);

            byte[] key = DeriveKey(password, salt);
            byte[] plainBytes = new byte[cipherBytes.Length];

            using (var aesGcm = new AesGcm(key, 16))
                aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            Array.Clear(key, 0, key.Length);
            return Encoding.UTF8.GetString(plainBytes);
        }

        private byte[] DeriveKey(string password, byte[] salt)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA256))
                return deriveBytes.GetBytes(32);
        }

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SecureMessageForm());
        }
    }

    public class RoundedTextBox : TextBox
    {
        private Color _borderColor = Color.FromArgb(200, 200, 220);

        [System.ComponentModel.Browsable(true)]
        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Visible)]
        public Color BorderColor
        {
            get => _borderColor;
            set
            {
                _borderColor = value;
                Invalidate();
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if (m.Msg == 0xF || m.Msg == 0x133)
            {
                using (Graphics g = Graphics.FromHwnd(Handle))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    using (Pen pen = new Pen(BorderColor, 2))
                    {
                        g.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
                    }
                }
            }
        }
    }

    public class ModernButton : Button
    {
        private Color _buttonColor = Color.FromArgb(0, 123, 255);
        private Color _hoverColor = Color.FromArgb(0, 100, 220);
        private bool isHovering = false;

        [System.ComponentModel.Browsable(true)]
        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Visible)]
        public Color ButtonColor
        {
            get => _buttonColor;
            set
            {
                _buttonColor = value;
                if (!isHovering) BackColor = value;
            }
        }

        [System.ComponentModel.Browsable(true)]
        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Visible)]
        public Color HoverColor
        {
            get => _hoverColor;
            set => _hoverColor = value;
        }

        public ModernButton()
        {
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            BackColor = ButtonColor;
            ForeColor = Color.White;
            Cursor = Cursors.Hand;

            MouseEnter += (s, e) => { isHovering = true; BackColor = HoverColor; };
            MouseLeave += (s, e) => { isHovering = false; BackColor = ButtonColor; };
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        }
    }
}