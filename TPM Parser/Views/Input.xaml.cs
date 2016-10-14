using System;
using Windows.UI.Xaml.Controls;
using Tpm2Lib;
using Windows.UI.Xaml.Input;

namespace TPM_Parser.Views
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class Input : Page
    {
        public Input()
        {
            this.InitializeComponent();

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
            // if format of line looks like from TPM driver trace, offer to reformat
            // if multi-line, trim and join to single line
            // remove spaces in stream
            // if it appears as if authorization section is censored, offer to replace with correct size values
            Output.Text = CommandProcessor.ParseCommand(CommandStream.Text);
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

    }
}
