using System;
using System.IO;
using System.Security.Cryptography;

namespace Unified.Encryption
{
  public class Decryptor
  {
    private DecryptTransformer transformer;

    private byte[] initVec;


    public byte[] IV
    {

      set
      {
        initVec = value;
      }
    }

    public Decryptor(EncryptionAlgorithm algId)
    {
      transformer = new DecryptTransformer(algId);
    }

    public byte[] Decrypt(byte[] bytesData, byte[] bytesKey)
    {
#if false
      MemoryStream memoryStream = new MemoryStream();
      transformer.IV = initVec;
      ICryptoTransform iCryptoTransform = transformer.GetCryptoServiceProvider(bytesKey);
      CryptoStream cryptoStream = new CryptoStream(memoryStream, iCryptoTransform, CryptoStreamMode.Write);
      try
      {
        cryptoStream.Write(bytesData, 0, (int)bytesData.Length);
        cryptoStream.FlushFinalBlock();
        cryptoStream.Close();
        byte[] bs = memoryStream.ToArray();
        return bs;
      }
      catch (Exception e)
      {
        throw new Exception(String.Concat("Error while writing encrypted data to the stream: \n", e.Message));
      }
#else
            if (bytesData==null)
                return null;

            Byte[] toEncryptArray = bytesData;

            RijndaelManaged rm = new RijndaelManaged
            {
                Key = bytesKey,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };

            ICryptoTransform cTransform = rm.CreateDecryptor();
            Byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return resultArray;
#endif
        }
    }

}
