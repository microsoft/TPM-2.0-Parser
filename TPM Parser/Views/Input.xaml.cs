using System;
using Windows.UI.Xaml.Controls;
using Tpm2Lib;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Navigation;

namespace TPM_Parser.Views
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class Input : Page
    {
        private readonly NavigationHelper m_NavigationHelper;
        private const string m_SettingCommandStream = "commandStream";
        private const string m_SettingDecodedCommand = "decodedCommand";
        private const string m_SettingDecodedCommandCode = "decodedCC";
        private TpmCc m_DecodedCommandCode = TpmCc.None;

        public Input()
        {
            this.InitializeComponent();
            this.m_NavigationHelper = new NavigationHelper(this);
            this.m_NavigationHelper.LoadState += LoadState;
            this.m_NavigationHelper.SaveState += SaveState;

            // testing only
            //CommandStream.Text = "8001000000160000017A00000006000001000000002A";
            //CommandStream.Text = "80020000003D00000158810000020000" +
            //    "0009AAAAAAAAAAAAAAAAAA00140151330A04AFD1010000000000000000000000" +
            //    "000010000000010004037FF700";
            //CommandStream.Text =
            //        "        0000  80020000 003D0000 01588100 00020000.....=...X......\r\n" +
            //        "        0010  0009AAAA AAAAAAAA AAAAAA00 14015133..............Q3\r\n" +
            //        "        0020  0A04AFD1 01000000 00000000 00000000................\r\n" +
            //        "        0030  00001000 00000100 04037FF7 00        .............\r\n";
        }

        private void Decode_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            TpmCc commandCode;
            Output.Text = CommandProcessor.ParseCommand(CommandStream.Text, out commandCode);
            if (m_DecodedCommandCode != commandCode &&
                commandCode != TpmCc.None)
            {
                m_DecodedCommandCode = commandCode;
            }
        }

        private void Input_KeyDown(object sender, KeyRoutedEventArgs e)
        {
            switch (e.Key)
            {
                case Windows.System.VirtualKey.Enter:
                    Decode_Click(sender, e);
                    break;
            }
        }

        #region Save and Restore state

        /// <summary>
        /// Populates the page with content passed during navigation. Any saved state is also
        /// provided when recreating a page from a prior session.
        /// </summary>
        /// <param name="sender">
        /// The source of the event; typically <see cref="NavigationHelper"/>.
        /// </param>
        /// <param name="e">Event data that provides both the navigation parameter passed to
        /// <see cref="Frame.Navigate(Type, Object)"/> when this page was initially requested and
        /// a dictionary of state preserved by this page during an earlier
        /// session. The state will be null the first time a page is visited.</param>
        private void LoadState(object sender, LoadStateEventArgs e)
        {
            if (SuspensionManager.SessionState.ContainsKey(m_SettingDecodedCommandCode))
            {
                int index;
                if (Int32.TryParse((string)SuspensionManager.SessionState[m_SettingDecodedCommandCode], out index))
                {
                    m_DecodedCommandCode = (TpmCc)index;
                }
            }

            if (SuspensionManager.SessionState.ContainsKey(m_SettingCommandStream))
            {
                CommandStream.Text = (string)SuspensionManager.SessionState[m_SettingCommandStream];
            }

            if (SuspensionManager.SessionState.ContainsKey(m_SettingDecodedCommand))
            {
                Output.Text = (string)SuspensionManager.SessionState[m_SettingDecodedCommand];
            }
        }

        /// <summary>
        /// Preserves state associated with this page in case the application is suspended or the
        /// page is discarded from the navigation cache. Values must conform to the serialization
        /// requirements of <see cref="SuspensionManager.SessionState"/>.
        /// </summary>
        /// <param name="sender">The source of the event; typically <see cref="NavigationHelper"/>.</param>
        /// <param name="e">Event data that provides an empty dictionary to be populated with
        /// serializable state.</param>
        private void SaveState(object sender, SaveStateEventArgs e)
        {
            SuspensionManager.SessionState[m_SettingDecodedCommandCode] = ((Int32)m_DecodedCommandCode).ToString();
            SuspensionManager.SessionState[m_SettingCommandStream] = CommandStream.Text;
            SuspensionManager.SessionState[m_SettingDecodedCommand] = Output.Text;
        }

        #endregion

        #region NavigationHelper registration

        /// <summary>
        /// The methods provided in this section are simply used to allow
        /// NavigationHelper to respond to the page's navigation methods.
        /// <para>
        /// Page specific logic should be placed in event handlers for the  
        /// <see cref="NavigationHelper.LoadState"/>
        /// and <see cref="NavigationHelper.SaveState"/>.
        /// The navigation parameter is available in the LoadState method 
        /// in addition to page state preserved during an earlier session.
        /// </para>
        /// </summary>
        /// <param name="e">Provides data for navigation methods and event
        /// handlers that cannot cancel the navigation request.</param>
        /// 
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            this.m_NavigationHelper.OnNavigatedTo(e);
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            this.m_NavigationHelper.OnNavigatedFrom(e);
        }

        #endregion

    }
}
