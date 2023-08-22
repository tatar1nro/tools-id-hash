using System.Text;

namespace Bro
{
    public static class IdHash
    {
        /*
            Encodes an integer ( id ) number into a readable hash string.
            Valid values from 0 to 1073741824 ( inclusively ).
            The hash string does not contain disputed characters lile 0/O I/L.
            Examples:
            0        = ZZZCZZ 
            1        = ACZZZZ 
            120851   = EJZZPC 
            83759123 = EF3ZR6 
        */
        
        public const int Max = 1073741824; // 32 ^ 6
        
        private const int Half = Max / 2;
        private const int MaxSymbols = 6;
        private const string Mask = "ZAHJRV5YU4SMGBX3CD6ET2PKNW18FQ97" /* 32 symbols 6 digits - 32^6 */;
        
        public static int Decode( string data )
        {
            data = data.ToUpper();
            var builder = new StringBuilder(data);
            var key = builder[0];
            data = key + builder.Remove(0, 1).ToString().DeShuffle((byte)key);
            
            var result = 0;
            for (var i = data.Length - 1; i >= 0; --i)
            {
                for( var j = 0; j < Mask.Length; ++j )
                {
                    if (  Mask[j] == data[i] )
                    {
                        result = result << 5; 
                        result = result | j;
                        break;
                    }
                }
            }
            result = ( result + Half ) % Max;
            return result;
        }
  
        public static string Encode( int identificator )
        {
            identificator = ( identificator + Half ) % Max;
            var result = string.Empty;
            var iterations = identificator < Max ? MaxSymbols : MaxSymbols + 1;
            for( var i = 0; i < iterations; ++ i )
            {
                var x32 = ( identificator & 31 );
                result += Mask[x32];
                identificator = identificator >> 5;
            }
          
            var builder = new StringBuilder(result);
            var key = builder[0];
            return key + builder.Remove(0, 1).ToString().Shuffle((byte)key);
        }
        
        public static bool IsValid(string hash)
        {
            if (hash != null && hash.Length == MaxSymbols)
            {
                hash = hash.ToUpper();
                foreach (var c in hash)
                {
                    if (!Mask.Contains(c))
                    {
                        return false;
                    }
                }

                return true;
            }
            return false;
        }
        
        /* Fisher–Yates shuffle https://en.wikipedia.org/wiki/Fisher–Yates_shuffle */
        private static int[] GetShuffleExchanges(int size, int key)
        {
            var exchanges = new int[size - 1];
            for (var i = size - 1; i > 0; i--)
            {
                var n = key % ( i + 1 ); 
                exchanges[size - 1 - i] = n;
            }
            return exchanges;
        }
        
        private static string Shuffle(this string toShuffle, byte key)
        {
            var size = toShuffle.Length;
            var chars = toShuffle.ToArray();
            var exchanges = GetShuffleExchanges(size, key);
            for (var i = size - 1; i > 0; i--)
            {
                var n = exchanges[size - 1 - i];
                var tmp = chars[i];
                chars[i] = chars[n];
                chars[n] = tmp;
            }
            return new string(chars);
        }

        private static string DeShuffle(this string shuffled, byte key)
        {
            var size = shuffled.Length;
            var chars = shuffled.ToArray();
            var exchanges = GetShuffleExchanges(size, key);
            for (var i = 1; i < size; i++)
            {
                var n = exchanges[size - i - 1];
                var tmp = chars[i];
                chars[i] = chars[n];
                chars[n] = tmp;
            }
            return new string(chars);
        }
    }
}