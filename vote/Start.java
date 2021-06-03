package vote;

import vote.Voter.*;
import vote.Validator.*;
import vote.Counter.*;

import java.lang.*;
import java.util.*;
import java.io.*;

public class Start
{
	public static void main(String[] args) throws IOException
	{
		if(args.length == 0)
			System.out.println("Please, specify the flag: \n\t -v - voter; \n\t -V - validator; -c - counter");
		if(args[0].equals("-v"))
		{
			VoterHundler.main(args);
		}
		else if(args[0].equals("-V"))
		{
			ValidatorHundler.main(args);
		}
		else if(args[0].equals("-c"))
		{
			CounterHundler.main(args);
		}
		else
		{
			System.out.println("Please, specify right flag: \n\t -v - voter; \n\t -V - validator; -c - counter");
		}
	}
}