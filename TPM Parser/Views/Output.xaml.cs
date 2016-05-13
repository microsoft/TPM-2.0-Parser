using System;
using Windows.UI.Xaml.Controls;
using Tpm2Lib;

namespace TPM_Parser.Views
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class Output : Page
    {
        public Output()
        {
            this.InitializeComponent();

            TpmCommands.Items.Clear();
            foreach (CommandInfo command in CommandInformation.Info)
            {
                TpmCommands.Items.Add(command.CommandCode.ToString());
            }
        }

        private void Decode_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            // if format of line looks like from TPM driver trace, offer to reformat
            // if multi-line, trim and join to single line
            // remove spaces in stream
            // if it appears as if authorization section is censored, offer to replace with correct size values
            DecodedResponse.Text = CommandProcessor.ParseResponse((string)TpmCommands.SelectedItem, ResponseStream.Text);
        }
    }
}
