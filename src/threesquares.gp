/*
Example usage:
? n=nextprime(10^220+30000)*nextprime(2^1000+40000000);n%8
%136 = 3
? t=threesquares(n);
? ##
  ***   last result computed in 2,210 ms.
? round(log(n))
%138 = 1200
*/

pl = 10^6;  \\ bound for trial division, may need change
default(primelimit, pl);

{
twosquares(n) =
    local(K, i, v, p, c1, c2);
    
    K = bnfinit(x^2 + 1);
    v = bnfisintnorm(K, n);
    
    for(i = 1, #v,
        p = v[i];
        c1 = polcoeff(p, 0);
        c2 = polcoeff(p, 1);
        
        if(denominator(c1) == 1 && denominator(c2) == 1,
            return([c1, c2])
        )
    );
    
    return([]);
}

{
threesquares(n) =
    local(m, z, i, x1, y1, j, fa, g);
    
    \\ Check if solution exists (Legendre's three-square theorem)
    if((n / (4^valuation(n, 4))) % 8 == 7,
        return([])
    );
    
    \\ Try different values of z
    for(z = 1, n,
        \\ Alternative: forstep(z = sqrtint(n), 1, -1,
        
        m = n - z^2;
        
        \\ Skip if m ≡ 3 (mod 4) - can't be sum of two squares
        if(m % 4 == 3, next);
        
        print1(z, " ");
        
        \\ Try to factor m with trial division
        fa = factor(m, pl);
        g = 1;
        
        \\ Check if factorization is complete and valid for two squares
        for(i = 1, #fa~,
            if(!ispseudoprime(fa[i,1]) || 
               (fa[i,2] % 2 == 1 && fa[i,1] % 4 == 3),
                g = 0;
                break
            )
        );
        
        if(!g, next);
        
        print("\nfound ", z, " m=", m, factor(m));
        
        \\ Find two squares representation
        j = twosquares(m);
        
        if(#j >= 2,
            x1 = abs(j[1]);
            y1 = abs(j[2]);
            print("RESULT:", x1, ",", y1, ",", z);
            return([x1, y1, z])
        );
    );
    
    return([]);  \\ No solution found
}