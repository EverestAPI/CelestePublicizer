using Celeste;

Player p = null!;
Console.WriteLine(p.jumpGraceTimer); // jumpGraceTimer is private in vanilla, but public now
p.PostCtor(); // PostCtor is added by Everest and remains private 