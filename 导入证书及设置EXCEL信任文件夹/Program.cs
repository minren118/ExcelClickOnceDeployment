using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
namespace 导入证书及设置EXCEL信任文件夹
{
    class Program
    {
        static void Main(string[] args)
        {
            //64位系统
            try
            {
                Console.WriteLine("正在导入证书操作");

                X509Store storeTrustedPublisher = new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser);
                //导入外部信任者
                ImportCertificate(storeTrustedPublisher);
                //导入根证书信任
                X509Store storeRoot = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
                ImportCertificate(storeRoot);

                Console.WriteLine("正在创建EXCEL信任文件夹");

                TrustDirSetting.SettingTrustDir("http://LiWeiJianWeb/");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Console.WriteLine("操作完成，请按任意键结束！");
                Console.ReadKey();
            }

        }

        private static void CreateTargetSubKey(RegisterManager registerManager, List<string> listSubKeys, RegistryKey localKey)
        {
            var regAllowNetworkLocations = listSubKeys.Where(s => s.EndsWith(@"Excel\Security\Trusted Locations"));
            //设置信任网络路径
            foreach (var item in regAllowNetworkLocations)
            {
                registerManager.SetRegeditKeyValue(item, "AllowNetworkLocations", "1");
            }

           
            //包含EXCEL字样的，并且有location节点
            var listSecurity = listSubKeys.Where(s => s.Contains(@"Excel\Security\Trusted Locations")).Where(s => Regex.IsMatch(s, @"Location\d+$")).ToList();

            foreach (var item in listSecurity)
            {
                if (registerManager.IsRegeditKeyAndValueExist(item, "Path", @"http://LiWeiJianWeb/"))
                {
                    return;
                }
            };

            var result = from s in listSecurity
                         select new { GroupName = Regex.Match(s, @".+?\\.+?\\.+?\\.+?\\").Value, Fullpath = s };

            //按HKEY_CURRENT_USER\Software\Microsoft\Office\15.0分组，防止多个EXCEL版本的原因引起信任位置添加不全
            var query = from s in result
                        group s by s.GroupName;

            foreach (var item in query)
            {
                //只取第1条记录，去掉最后一个尾数
                string locationName = Regex.Match(item.First().Fullpath, @".+Location").Value;
                //用最后的尾数来比较大小，不是用字符串，可以最终比较出11比2大
                int locationIndex = item.Max(s => int.Parse(Regex.Match(s.Fullpath, @".+Location(\d+)").Groups[1].Value) + 1);
                string newLocationName = Regex.Match(locationName, ".+Location").Value + locationIndex;
                RegistryKey Location = localKey.CreateSubKey(newLocationName);
                Location.SetValue("Path", @"http://LiWeiJianWeb/");
                Location.SetValue("AllowSubfolders", "00000001", RegistryValueKind.DWord);
                Location.SetValue("Date", DateTime.Now.ToString());
                Location.SetValue("Description", "");
            }
        }


        private static void ImportCertificate(X509Store store)
        {
            store.Open(OpenFlags.ReadWrite);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, "Excel催化剂", false);

            if (certs.Count == 0 || certs[0].NotAfter < DateTime.Now)
            {
                X509Certificate2 certificate = new X509Certificate2(Resource1.Excel催化剂);
                store.Remove(certificate);   //可省略
                store.Add(certificate);
                store.Close();
            }
        }
    }
}
