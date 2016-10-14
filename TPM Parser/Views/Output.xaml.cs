using System;
using Windows.UI.Xaml.Controls;
using Tpm2Lib;
using System.Collections;
using Windows.UI.Xaml.Input;

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

            string[] commandNames = new string[CommandInformation.Info.Length];
            int i = 0;
            foreach (CommandInfo command in CommandInformation.Info)
            {
                commandNames[i++] = command.CommandCode.ToString();
            }

            Array.Sort(commandNames, new CaseInsensitiveComparer());

            TpmCommands.Items.Clear();
            foreach (string command in commandNames)
            {
                TpmCommands.Items.Add(command);
            }

            // testing only
            //ResponseStream.Text = "80010000016300000000010000000600" +
            //    "00002A00000100322E3000000001010000000000000102000000740000010300" +
            //    "00012F00000104000007DE000001054946580000000106534C42390000010736" +
            //    "363500000001080000000000000109000000000000010A000000000000010B00" +
            //    "0500280000010C0007B3020000010D000004000000010E000000030000010F00" +
            //    "0000070000011000000003000001110000004000000112000000180000011300" +
            //    "000003000001140000FFFF000001160000000800000117000006800000011800" +
            //    "00000600000119000800000000011A0000000B0000011B000000060000011C00" +
            //    "0000800000011D000000FF0000011E000005000000011F000005000000012000" +
            //    "000020000001210000039600000122000000EB00000123000000010000012400" +
            //    "0000000000012500000100000001260000000000000127000000000000012800" +
            //    "000080000001290000005A0000012A00000058";
            //ResponseStream.Text = // Quote
            //    "80020000019400000000000001810079" +
            //    "FF54434780180022000B9E54EB30B000" +
            //    "3CCADB310F90E6A2BFF824BCDACBDAF7" +
            //    "E67935FE27EEDAA5D00C00140151330A" +
            //    "04AFD101000000000000000000000000" +
            //    "000000003B48837CA18EAC67A5598DEB" +
            //    "005EAFBF0ECBD8E6D000000001000403" +
            //    "7FF7000014FAE29AA727E58E56F59729" +
            //    "DF6EBA038A888EFB920014000401009D" +
            //    "078F73A073A40B5DB83EDF2A7C424C1C" +
            //    "7319BC156A0BB8DB07870C9F5FC31C6A" +
            //    "7353DF95501F9CB3AD0E4B591FD8F1C9" +
            //    "DFC620D43E3B2BAD5449B84C21F30FAF" +
            //    "13509A5AA9C9D061719697618E7FC5E5" +
            //    "B117B777B40A3532D461D353C0F89042" +
            //    "4E67834DF94D568606E132B371633CD1" +
            //    "601A3A83418FABA4FB72913CE1B13A69" +
            //    "22DCC43C6C32A3568D835308FCD88DD6" +
            //    "A6E69962DB3A9F9C96257FA074A2074B" +
            //    "B8538D25B593B6F5060AE0F9D105B724" +
            //    "651E07098340CA97D49A7E92BA58E35C" +
            //    "FE220F275AA9EFD74C6A43EEEC0BF1DE" +
            //    "3C6CFA5E6F01933F881145B37B6D6A79" +
            //    "75A52F89FB19539B70B2368F9F88DD26" +
            //    "B5B22BAB88BD5498511F06DB35693700" +
            //    "00010000";
            //ResponseStream.Text =
            //    "        0000  80020000 01940000 00000000 01810079...............y\r\n" +
            //    "        0010  FF544347 80180022 000B9E54 EB30B000  .TCG...\"...T.0..\r\n" +
            //    "        0020  3CCADB31 0F90E6A2 BFF824BC DACBDAF7 <..1......$.....\r\n" +
            //    "        0030  E67935FE 27EEDAA5 D00C0014 0151330A.y5.'........Q3.\r\n" +
            //    "        0040  04AFD101 00000000 00000000 00000000................\r\n" +
            //    "        0050  00000000 3B48837C A18EAC67 A5598DEB....; H.|...g.Y..\r\n" +
            //    "        0060  005EAFBF 0ECBD8E6 D0000000 01000403.^..............\r\n" +
            //    "        0070  7FF70000 14FAE29A A727E58E 56F59729.........'..V..)\r\n" +
            //    "        0080  DF6EBA03 8A888EFB 92001400 0401009D.n..............\r\n" +
            //    "        0090  078F73A0 73A40B5D B83EDF2A 7C424C1C..s.s..].>.*| BL.\r\n" +
            //    "        00A0  7319BC15 6A0BB8DB 07870C9F 5FC31C6A s...j......._..j\r\n" +
            //    "        00B0  7353DF95 501F9CB3 AD0E4B59 1FD8F1C9 sS..P.....KY....\r\n" +
            //    "        00C0 DFC620D4 3E3B2BAD 5449B84C 21F30FAF.. .>; +.TI.L!...\r\n" +
            //    "        00D0  13509A5A A9C9D061 71969761 8E7FC5E5.P.Z...aq..a....\r\n" +
            //    "        00E0  B117B777 B40A3532 D461D353 C0F89042  ...w..52.a.S...B\r\n" +
            //    "        00F0  4E67834D F94D5686 06E132B3 71633CD1 Ng.M.MV...2.qc <.\r\n" +
            //    "        0100  601A3A83 418FABA4 FB72913C E1B13A69  `.:.A....r.<..:i\r\n" +
            //    "        0110  22DCC43C 6C32A356 8D835308 FCD88DD6  \"..<l2.V..S.....\r\n" +
            //    "        0120  A6E69962 DB3A9F9C 96257FA0 74A2074B...b.:...%..t..K\r\n" +
            //    "        0130  B8538D25 B593B6F5 060AE0F9 D105B724  .S.%...........$\r\n" +
            //    "        0140  651E0709 8340CA97 D49A7E92 BA58E35C e....@....~..X.\\\r\n" +
            //    "        0150  FE220F27 5AA9EFD7 4C6A43EE EC0BF1DE  .\".'Z...LjC.....\r\n" +
            //    "        0160  3C6CFA5E 6F01933F 881145B3 7B6D6A79 < l.^ o..?..E.{mjy\r\n" +
            //    "        0170  75A52F89 FB19539B 70B2368F 9F88DD26 u./...S.p.6....&\r\n" +
            //    "        0180  B5B22BAB 88BD5498 511F06DB 35693700..+...T.Q...5i7.\r\n" +
            //    "        0190  00010000....\r\n";
        }

        private void Decode_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            // if format of line looks like from TPM driver trace, offer to reformat
            // if multi-line, trim and join to single line
            // remove spaces in stream
            // if it appears as if authorization section is censored, offer to replace with correct size values
            DecodedResponse.Text = CommandProcessor.ParseResponse((string)TpmCommands.SelectedItem, ResponseStream.Text);
        }

        private void Output_KeyDown(object sender, KeyRoutedEventArgs e)
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
