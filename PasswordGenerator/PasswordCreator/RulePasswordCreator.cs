using System.Collections.Generic;

namespace PasswordGenerator.PasswordCreator
{
    public class RulePasswordCreator : IPasswordCreator
    {
        private static readonly string filename = "../../../Resources/millionpasswords.txt";
        
        private HumanPasswordsCreator HumanCreator = new(filename);
        
        private RandomPasswordCreator RandomCreator = new();

        private static readonly int leftBound = 6;

        public List<string> GeneratePasswords(int amount)
        {
            var humanPwdList = HumanCreator.GeneratePasswords(amount);
            var randomPwdList = RandomCreator.GeneratePasswords(amount);

            var lst = new List<string>();

            for (var i = 0; i < amount; i++)
            {
                lst.Add(ExecuteRule(humanPwdList[i] + randomPwdList[i].Substring(0,leftBound)));
            }

            return lst;
        }

        private string ExecuteRule(string str)
        {            
            str.Replace("for", "4");
            str.Replace("too", "2");
            str.Replace("i", "!");
            str.Replace("I", "!");
            str.Replace("o", "0");
            str.Replace("oo", "u");
            str.Replace("o", "0");
            str.Replace("l", "1");
            str.Replace("O", "0");
            str.Replace("I", "1");
            
            return str;
        }
    }
}