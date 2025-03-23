using System;

class Class : Interface
{
    static int sfield;

    int field;

    static Enum enumfield;

    static Class()
    {
        Class.enumfield = Enum.Second;
    }

    unsafe void Method(bool* pointer, ref bool reference, bool[] array)
    {
        Class.sfield++;
        this.field++;
    }

    static void StaticGenericMethod<T, U>(T t, U u)
    {

    }

    class InnerClass
    {
        class InnerInnerClass
        {

        }
    }
}

public class OverloadTest {
    public int a;

    public OverloadTest(int b)
    {
        this.a = b;
    }

    public int A(Child3 instance)
    {
        return 2;
    }

    public int A(Root instance)
    {
        return 0;
    }

    public int A(Child1 instance) 
    {
        return 1;
    }

    public int A(Child4<Root> instance)
    {
        return 4;
    }

    public int A<T>(Child4<Child4<T>> instance)
    {
        return 5;
    }

    public int A(Child41<Child1, Child2> instance)
    {
        return 6;
    }

    public int B(Root a, Child1 b)
    {
        return 0;
    }

    public int B(Child1 a, Root b)
    {
        return 1;
    }

    public int C()
    {
        return 0;
    }

    public int C(int value)
    {
        return value;
    }

    public static int D(Child1 a)
    {
        return 0;
    }

    public int D(Root a)
    {
        return this.a;
    }

    public static int E(Child11 a, Root b)
    {
        return 0;
    }

    public static int E(Root a, Child1 b)
    {
        return 1;
    }

    public class Nested : OverloadTest
    {
        public Nested(int b) : base(b)
        {
        }

        public int A(Child2 instance)
        {
            return 3;
        }

        public new int C()
        {
            return 2;
        }
    }

    public class Root
    {
    }

    public class Child1 : Root
    {
    }

    public class Child11 : Child1
    {
    }

    public class Child2 : Root
    {
    }

    public class Child3 : Root
    {
    }

    public class Child31 : Child3
    {
    }

    public class Child311 : Child31
    {
    }

    public class Child4<T> : Root
    {
    }

    public class Child41<T, U> : Child4<T>
    {
    }
}

abstract class AbstractGenericClass<T, U>
{

}

class PartiallyInflatedClass<T> : AbstractGenericClass<T, String>
{

}

class InflatedClass : AbstractGenericClass<String, String>
{

}

struct Struct
{

}

struct EmptyStruct
{

}

public class Il2CppObjectTest
{
    public static int F;

    public static int A(int a)
    {
        return 0;
    }

    public int A (string a)
    {
        return 1;
    }

    public static int B()
    {
        return 2;
    }

    public static int C(int a)
    {
        return 3;
    }

    public int C()
    {
        return 4;
    }

    public class BaseTest : Il2CppObjectTest {
        public Il2CppObjectTest D()
        {
            return this;
        }
    }
}

enum Enum
{
    First,
    Second,
    Third
}

enum LongEnum : ulong
{
    First,
    Second,
    Third
}

enum EmptyEnum
{

}


interface Interface
{

}

namespace MethodInflateTest {
    class Parent<ClassType> {
        static int A<T>() {
            return 0;
        }

        static int A<T, U>() {
            return 1;
        }

        static int B() {
            return 0;
        }

        static int B<T>(T a) {
            return 1;
        }

        static int B<T, U>() {
            return 2;
        }

        static int C(ClassType a) {
            return 0;
        }

        static int C<T>(T a) {
            return 1;
        }

        static int C<T>(String a) {
            return 2;
        }
        
        static int D(ClassType a) {
            return 0;
        }
    }

    class Child : Parent<System.Object> {
        static int A<T, U, V>() {
            return 3;
        }
    }
}
