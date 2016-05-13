using System;
using Windows.UI.Xaml.Controls;
using Tpm2Lib;

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
        }

        private void Decode_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            // if format of line looks like from TPM driver trace, offer to reformat
            // if multi-line, trim and join to single line
            // remove spaces in stream
            // if it appears as if authorization section is censored, offer to replace with correct size values
            Output.Text = CommandProcessor.ParseCommand(CommandStream.Text);
        }
    }
}
