using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PasswordGenerator.Hashes;
using PasswordGenerator.PasswordCreator;

class Program
{
    static void Main()
    {
        List<IPasswordCreator> lst = new ()
        {
            new HumanPasswordsCreator("../../../Resources/millionpasswords.txt"),
            new HumanPasswordsCreator("../../../Resources/50passwords.txt"),
            new RandomPasswordCreator(),
            new RulePasswordCreator()
        };

        List<string> pwd = new();
        
        pwd.AddRange(lst[0].GeneratePasswords(70000));
        pwd.AddRange(lst[1].GeneratePasswords(10000));
        pwd.AddRange(lst[2].GeneratePasswords(5000));
        pwd.AddRange(lst[3].GeneratePasswords(15000));
        
        var rnd = new Random();
        var orderedEnumerable = pwd.OrderBy(item => rnd.Next());

        var shaHashes = new List<string>();
        var argonHashes = new List<string>();
        var argon = new Argon2i();
        foreach (var p in orderedEnumerable)
        {
            shaHashes.Add(BitConverter.ToString(SimpleSha1.GenerateHash(p)).Replace("-", ""));
            
            var salt = argon.GenerateRandomSequence(16);
            var saltHex = BitConverter.ToString(salt).Replace("-", "");
            var hashedHex = BitConverter.ToString(argon.HashPassword(p, salt)).Replace("-", "");
            argonHashes.Add($"{saltHex};{hashedHex}");
        }

        File.WriteAllLines("passwords.csv", orderedEnumerable);
        File.WriteAllLines("hashes.csv", shaHashes);
        File.WriteAllLines("saltedhashes.csv", argonHashes);

    }
}