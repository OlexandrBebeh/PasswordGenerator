using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PasswordGenerator.PasswordCreator
{
    public class HumanPasswordsCreator : IPasswordCreator
    {
        private string fileName;

        private List<string> passwordPool = new ();

        private Random rand = new ();
        
        private void InitPool()
        {
            var lines = File.ReadLines(fileName);

            var enumerable = lines as string[] ?? lines.ToArray();
            for (var i = 0; i < enumerable.Length; i++)
            {
                passwordPool.Add(enumerable[i]);
            } 
        }
        
        public HumanPasswordsCreator(string name)
        {
            fileName = name;

            InitPool();
        }

        public List<string> GeneratePasswords(int amount)
        {
            var lst = new List<string>();

            for (var i = 0; i < amount; i++)
            {
                lst.Add(passwordPool[rand.Next() % passwordPool.Count]);
            }

            return lst;
        }
    }
}