using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace PaddedOracle
{
    class Program
    {
        private static int BLOCK_SIZE = 16;
        static void Main(string[] args)
        {
            RunServer(".", 5000);
        }

        static void RunServer(string keypath, int portNumber)
        {
            const string SERVER_IP = "127.0.0.1";
            IPAddress localAddress = IPAddress.Parse(SERVER_IP);
            TcpListener listener = new TcpListener(localAddress, portNumber);

            listener.Start();
            TcpClient client = listener.AcceptTcpClient();
            NetworkStream nwStream = client.GetStream();
            byte[] buffer = new byte[client.ReceiveBufferSize];

            // read in the key
            var keyText = File.ReadAllLines("key.txt")[0].Trim();
            byte[] key = Enumerable.Range(0, keyText.Length)
                                   .Where(x => x % 2 == 0)
                                   .Select(x => Convert.ToByte(keyText.Substring(x, 2), 16))
                                   .ToArray();
            bool exit = false;
            while (!exit)
            {
                // determine the size of the message
                // will limit to 255 bytes
                int bytesRead = nwStream.Read(buffer, 0, 1);
                if (bytesRead != 1)
                {
                    Console.WriteLine("Unable to determine the length of the message, going to be lame and bail! ^^");
                }
                else
                {
                    int messageLength = (int) ((uint) buffer[0]);
                    Console.WriteLine("Message length: {0}", messageLength);
                    int totalBytesRead = 0;
                    int bytesToRead = 0;
                    if (client.ReceiveBufferSize > messageLength) 
                        bytesToRead = messageLength;
                    else
                        bytesToRead = client.ReceiveBufferSize;
                    byte[] data = new byte[messageLength];
                    while (totalBytesRead < messageLength) 
                    {
                        // get new data
                        bytesRead = nwStream.Read(buffer, 0, bytesToRead);
                        
                        // copy into buffer for decryption
                        Array.Copy(buffer, 0, data, totalBytesRead, bytesRead);

                        // determine how many bytes left to accept
                        totalBytesRead += bytesRead;
                        bytesToRead = messageLength - totalBytesRead;
                        if (client.ReceiveBufferSize < bytesToRead)
                            bytesToRead = client.ReceiveBufferSize;

                        
                    }
                    // check to see if message is "exit", and stop the program if so
                    if (messageLength == 4)
                    {
                        var contents = System.Text.Encoding.UTF8.GetString(data);
                        if (contents == "exit")
                            exit = true;
                    }
                    // attempt to perform the decryption
                    else
                    {
                        try
                        {
                            DecryptStringFromBytes_Aes(data, key);
                            nwStream.WriteByte((Byte)'y');
                        }
                        catch (Exception e)
                        {
                            nwStream.WriteByte((Byte)'n');
                        }
                    }
                    
                }
            }

        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");

            string plainText = null;
            
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Key = Key;
                
                var IV = new byte[BLOCK_SIZE];
                Array.Copy(cipherText, IV, BLOCK_SIZE);
                aesAlg.IV = IV;

                byte[] encryptedMessage = new byte[cipherText.Length - BLOCK_SIZE];
                Array.Copy(cipherText, BLOCK_SIZE, encryptedMessage, 0, encryptedMessage.Length);
                
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(encryptedMessage))
                {
                    using (CryptoStream csDescrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDescrypt))
                        {
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }

                return plainText;
            }
        }
    }

    
}
