using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using PasswordGenerator.Hashes;
using PasswordGenerator.PasswordCreator;

class Program
{
    private const int NumberOfThread = 16;
    private static object locker = new();

    static void Main()
    {
        // GeneratePasswords();
        TryBreakArgon();
    }

    private static void GeneratePasswords()
    {
        List<IPasswordCreator> lst = new()
        {
            new HumanPasswordsCreator(GetPathInProject("Resources/millionpasswords.txt")),
            new HumanPasswordsCreator(GetPathInProject("Resources/50passwords.txt")),
            new RandomPasswordCreator(),
            new RulePasswordCreator()
        };

        List<string> pwd = new();

        pwd.AddRange(lst[0].GeneratePasswords(10000));
        pwd.AddRange(lst[1].GeneratePasswords(10000));
        pwd.AddRange(lst[2].GeneratePasswords(10000));
        pwd.AddRange(lst[3].GeneratePasswords(10000));

        var rnd = new Random();
        var orderedEnumerable = pwd.OrderBy(item => rnd.Next());

        var shaHashes = new List<string>();
        var argonHashes = new List<string>();
        var saltedHashes = new List<string>();

        var argon = new Argon2i();
        foreach (var p in orderedEnumerable)
        {
            shaHashes.Add(BitConverter.ToString(SimpleSha1.GenerateHash(p)).Replace("-", ""));

            var salt = argon.GenerateRandomSequence(16);
            var saltHex = BitConverter.ToString(salt).Replace("-", "");
            var hashedHex = BitConverter.ToString(argon.HashPassword(p, salt)).Replace("-", "");

            argonHashes.Add($"{Encoding.Default.GetString(argon.HashPasswordWithSalt(p))}");

            saltedHashes.Add($"{hashedHex};{saltHex}");
        }

        File.WriteAllLines("passwords.csv", orderedEnumerable);
        File.WriteAllLines("hashes.csv", shaHashes);
        File.WriteAllLines("saltedhashes.csv", saltedHashes);
        File.WriteAllLines("argonhashes.csv", argonHashes);
    }

    private static void TryBreakArgon()
    {
        var argon = new Argon2i(4096 * 1024, 3);
        var passwords = ReadPasswords();
        var hashes = ReadHashes();
        var foundPasswords = new Dictionary<string, string>();
        var threads = new Thread[NumberOfThread];
        var numberOfPasswords = passwords.Length / NumberOfThread;
        var extra = passwords.Length % NumberOfThread;
        for (var i = 0; i < NumberOfThread; i++)
        {
            var number = i < extra ? numberOfPasswords + 1 : numberOfPasswords;
            var skippedPasswords = i * numberOfPasswords + (extra - Math.Max(0, extra - i));
            var threadPasswords = passwords.Skip(skippedPasswords).Take(number);
            threads[i] = new Thread(() => ProcessPasswords(argon, threadPasswords, hashes, foundPasswords));
            threads[i].Start();
        }
        foreach (var thread in threads)
        {
            thread.Join();
        }

        var builder = new StringBuilder();
        foreach (var (h, p) in foundPasswords)
        {
            builder.Append(h);
            builder.Append(" -> ");
            builder.Append(p);
        }

        Console.WriteLine($"Found: {foundPasswords.Count}");
        File.WriteAllText(GetPathInProject("Resources/strong_cracked.txt"), builder.ToString());
    }

    private static void ProcessPasswords(Argon2i argon, IEnumerable<string> passwords, string[] hashes,
        Dictionary<string, string> foundPasswords)
    {
        foreach (var password in passwords)
        {
            Console.WriteLine($"Processing {password}");
            foreach (var hash in hashes)
            {
                if (argon.Verify(password, hash))
                {
                    Console.WriteLine($"Found password: {hash} -> {password}");
                    foundPasswords[hash] = password;
                    Save(hash, password);
                }
            }
        }
    }

    private static void Save(string hash, string password)
    {
        lock (locker)
        {
            using var w = File.AppendText(GetPathInProject("Resources/strong_cracked.txt"));
            w.WriteLine($"{hash} -> {password}");
            w.Flush();
        }
    }

    private static string[] ReadPasswords()
    {
        return File.ReadAllLines(GetPathInProject("Resources/common_passwords.txt"));
    }

    private static string[] ReadHashes()
    {
        return File.ReadAllLines(GetPathInProject("Resources/strong_hashes.txt"));
    }

    private static string GetPathInProject(string path)
    {
        return $"../../../{path}";
    }
}
