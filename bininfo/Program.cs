using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace bininfo
{
    class Program
    {
        static void Main(string[] args)
        {
            var parser = new CommandLine();
            parser.Parse(args);

            if (parser.Arguments.Count > 0)
            {
                string filePath = String.Empty;
                bool genMD5 = false;
                // User must specify a fully qualified path
                if (parser.Arguments.ContainsKey("file"))
                {
                    filePath = parser.Arguments["file"][0];
                    // Check if file exist
                    if (!File.Exists(filePath))
                    {
                        Console.WriteLine("Cannot find" + filePath + "Exiting");
                    }
                }
                else
                {
                    usage();
                }

                // Check for optional md5 option
                if (parser.Arguments.ContainsKey("md5"))
                {
                    genMD5 = true;
                }

                var arch = GetArch(filePath);
                var version = GetFileVersion(filePath);
                string md5 = String.Empty;
                if (genMD5)
                {
                    md5 = GetMd5String(filePath);
                }
                Console.WriteLine(String.Format("{0}, {1}, {2}", arch, version, md5));
            }
            else
            {
                usage();
            }
        }
        static void usage()
        {
            Console.WriteLine("bininfo -file filePath [md5]");
        }


        /// <summary>
        ///  Returns file version of given binary
        /// </summary>
        /// <param name="binPath"></param>
        /// <returns></returns>
        public static string GetFileVersion(string binFile)
        {
            if (binFile == null)
            {
                throw new ArgumentNullException();
            }

            FileVersionInfo myFileVersionInfo = FileVersionInfo.GetVersionInfo(binFile);
            return myFileVersionInfo.FileVersion;
        }
        /// <summary>
        /// Returns x86 or x64
        /// </summary>
        /// <param name="binPath"></param>
        /// <returns></returns>
        public static string GetArch(string binFile)
        {
            if (binFile == null)
            {
                throw new ArgumentNullException();
            }

            string arch = String.Empty;

            if (binFile == null)
            {
                throw new ArgumentNullException();
            }

            var is64bit = UnmanagedDllIs64Bit(binFile);

            switch (is64bit)
            { 
                case true :
                    arch = "x64";
                    break;
                case false:
                    arch = "x86";
                    break;
                default:
                    throw new Exception("Unable to determine architecture");
            }

            return arch;
        }
        /// <summary>
        /// Returns MachineType
        /// </summary>
        /// <param name="binPath"></param>
        /// <returns></returns>
        public static MachineType GetDllMachineType(string binPath)
        {
            if (binPath == null)
            {
                throw new ArgumentNullException();
            }

            //see http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
            //offset to PE header is always at 0x3C
            //PE header starts with "PE\0\0" =  0x50 0x45 0x00 0x00
            //followed by 2-byte machine type field (see document above for enum)

            FileStream fs = new FileStream(binPath, FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            fs.Seek(0x3c, SeekOrigin.Begin);
            Int32 peOffset = br.ReadInt32();
            fs.Seek(peOffset, SeekOrigin.Begin);
            UInt32 peHead = br.ReadUInt32();
            if (peHead != 0x00004550) // "PE\0\0", little-endian
                throw new Exception("Can't find PE header");
            MachineType machineType = (MachineType)br.ReadUInt16();
            br.Close();
            fs.Close();
            return machineType;
        }

        /// <summary>
        /// Calculates and returns MD5 of a given file
        /// </summary>
        /// <param name="binFile"></param>
        /// <returns></returns>
        public static string GetMd5String(string binFile)
        {
            if (binFile == null)
            {
                throw new ArgumentNullException();
            }

            try
            {
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(binFile))
                    {
                        // Compute MD5 hash of file
                        byte[] data = md5.ComputeHash(stream);

                        // Create a new Stringbuilder to collect the bytes
                        // and create a string.
                        StringBuilder sBuilder = new StringBuilder();

                        // Loop through each byte of the hashed data
                        // and format each one as a hexadecimal string.
                        for (int i = 0; i < data.Length; i++)
                        {
                            sBuilder.Append(data[i].ToString("x2"));
                        }

                        // Return the hexadecimal string.
                        return sBuilder.ToString();
                    }
                }
            }
            catch (Exception)
            {
                throw;
            }
        }

        public enum MachineType : ushort
        {
            IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
            IMAGE_FILE_MACHINE_AM33 = 0x1d3,
            IMAGE_FILE_MACHINE_AMD64 = 0x8664,
            IMAGE_FILE_MACHINE_ARM = 0x1c0,
            IMAGE_FILE_MACHINE_EBC = 0xebc,
            IMAGE_FILE_MACHINE_I386 = 0x14c,
            IMAGE_FILE_MACHINE_IA64 = 0x200,
            IMAGE_FILE_MACHINE_M32R = 0x9041,
            IMAGE_FILE_MACHINE_MIPS16 = 0x266,
            IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
            IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
            IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
            IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
            IMAGE_FILE_MACHINE_R4000 = 0x166,
            IMAGE_FILE_MACHINE_SH3 = 0x1a2,
            IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
            IMAGE_FILE_MACHINE_SH4 = 0x1a6,
            IMAGE_FILE_MACHINE_SH5 = 0x1a8,
            IMAGE_FILE_MACHINE_THUMB = 0x1c2,
            IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
        }

        /// <summary>
        /// returns true if the dll is 64-bit, false if 32-bit, and null if unknown 
        /// </summary>
        /// <param name="binFile"></param>
        /// <returns></returns>
        public static bool? UnmanagedDllIs64Bit(string binFile)
        {
            if (binFile == null)
            {
                throw new ArgumentNullException();
            }

            switch (GetDllMachineType(binFile))
            {
                case MachineType.IMAGE_FILE_MACHINE_AMD64:
                case MachineType.IMAGE_FILE_MACHINE_IA64:
                    return true;
                case MachineType.IMAGE_FILE_MACHINE_I386:
                    return false;
                default:
                    return null;
            }
        }
    }
}
