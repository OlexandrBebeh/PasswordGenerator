using System;
using System.Collections.Generic;
using System.Linq;

namespace PasswordGenerator.PasswordCreator
{
    public class RandomPasswordCreator : IPasswordCreator
    {
        private const int MinLength = 8;
        private const int range = 4;

        private Random rand = new ();

        const string charsPool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        
        public List<string> GeneratePasswords(int amount)
        {
            var lst = new List<string>();

            for (var i = 0; i < amount; i++)
            {
                var len = rand.Next() % range + MinLength;

                lst.Add(new string(Enumerable.Repeat(charsPool, len)
                    .Select(s => s[rand.Next(s.Length)]).ToArray()));
            }

            return lst;
        }
    }
}