pl = 10^6;
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
    
    if((n / (4^valuation(n, 4))) % 8 == 7,
        return([])
    );
    
    for(z = 1, n,
        m = n - z^2;
        
        if(m % 4 == 3, next);
        
        fa = factor(m, pl);
        g = 1;
        
        for(i = 1, #fa~,
            if(!ispseudoprime(fa[i,1]) || 
               (fa[i,2] % 2 == 1 && fa[i,1] % 4 == 3),
                g = 0;
                break
            )
        );
        
        if(!g, next);
        
        j = twosquares(m);
        
        if(#j >= 2,
            x1 = abs(j[1]);
            y1 = abs(j[2]);
            return([x1, y1, z])
        );
    );
    
    return([]);
}

{
compute_decomposition(value) =
    local(result);
    result = threesquares(value);
    if(#result == 0,
        print("Error: Cannot compute three squares decomposition for ", value);
        return([0, 0, 0])
    );
    return(result);
}

/* Main function for external calls */
{
main() =
    local(n, result);
    read("input.tmp");
    result = compute_decomposition(n);
    write("output.tmp", result[1], " ", result[2], " ", result[3]);
    quit;
}