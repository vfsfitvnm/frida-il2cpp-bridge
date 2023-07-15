using System;

namespace HelloWorld
{
    enum Season
    {
        Spring,
        Summer,
        Autumn,
        Winter
    }

    public struct Coords
    {
        public Coords(double x, double y)
        {
            this.x = x;
            this.y = y;
        }

        public double x;
        public double y;

        public override string ToString() {
            return string.Format("({0}; {1})", this.x, this.y);
        }
    }

    class Program
    {
        static Season NextSeason(Season season) {
            switch (season)
            {
                case Season.Spring:
                    return Season.Summer;
                case Season.Summer:
                    return Season.Autumn;
                case Season.Autumn:
                    return Season.Winter;
                case Season.Winter:
                    return Season.Spring;
                default:
                    return Season.Spring;
            }
        }

        static Coords IncrCoords(Coords coords) {
            return new Coords(coords.x + 1, coords.y + 1);
        }

        static void Main(string[] args) {
            var a = 1;
            var b = 2;
            Console.WriteLine("Hello World: {0}", a + b);
        }
    }
}
