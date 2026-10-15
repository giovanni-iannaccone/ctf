#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>

class Human
{
private:
	virtual void give_shell()
    {
		system("/bin/sh");
	}

protected:
	int age;
    std::string name;
    
public:
	virtual void introduce()
    {
		std::cout << "My name is " << name << std::endl;
		std::cout << "I am " << age << " years old" << std::endl;
	}
};

class Man: public Human
{
public:
	Man(std::string name, int age)
    {
		this->name = name;
		this->age = age;
    }
    
    virtual void introduce()
    {
		Human::introduce();
        std::cout << "I am a nice guy!" << std::endl;
    }
};

class Woman: public Human
{
public:
    Woman(std::string name, int age)
    {
        this->name = name;
        this->age = age;
    }
    
    virtual void introduce()
    {
        Human::introduce();
        std::cout << "I am a cute girl!" << std::endl;
    }
};

int main(int argc, char **argv)
{
	Human *m = new Man("Jack", 25);
	Human *w = new Woman("Jill", 21);

	size_t len;
	char *data;
	unsigned int op;
    
    do {
        std::cout << "1. use\n2. after\n3. free\n";
        std::cin >> op;

		switch (op) {
			case 1:
				m->introduce();
				w->introduce();
				break;
                
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				std::cout << "your data is allocated" << std::endl;
				break;
                
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	} while (1);

	return 0;	
}
