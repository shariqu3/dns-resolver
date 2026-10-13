#include "pch.h"
using namespace std;
void process()
{
	vector<int> lol_count, lol_pos;
	int earliest_occurence = INT_MAX, truncated = 0;
	for (int i = 1;i <= 1000;i++)
	{
		string file_name = "C:\\Users\\Sharique\\source\\csce612_hw2\\x64\\Release\\output" + to_string(i) + ".txt";
		char* s = file_name.data();
		//printf("%s", s);
		ifstream file(file_name);
		string t;
		int count = 0, pos=0;
		while (getline(file, t))
		{
			if (*t.rbegin() == 'o')
				truncated++;
			pos = t.find("lol", pos);
			lol_pos.push_back(pos);
			while (pos + 2 < t.length())
			{
				if (t[pos] == 'l' && t[pos + 1] == 'o' && t[pos + 2] == 'l')
				{
					pos += 3;
					count++;
				}
				else
					break;
			}
		}
		lol_count.push_back(count);
		file.close();
	}
	cout << "min :" << *min_element(lol_count.begin(), lol_count.end())<<" max: "<<*max_element(lol_count.begin(), lol_count.end())<<'\n';
	cout << "truncated lols: " << truncated<<'\n';
}