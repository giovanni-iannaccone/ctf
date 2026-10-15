// some experiments I made to
// understand c++ object layout

#include <fcntl.h>
#include <iomanip>
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
    Human() {}

    Human(int age, const std::string &name)
        : age(age), name(name) {}

	virtual void introduce()
    {
		std::cout << "My name is " << name << std::endl;
		std::cout << "I am " << age << " years old" << std::endl;
	}
};

class Man: public Human
{
public:
    Man(int age, const std::string &name)
    {
        this->age = age;
        this->name = name;
    }
    
    virtual void introduce()
    {
		Human::introduce();
        std::cout << "I am a nice guy!" << std::endl;
    }
};

void print_raw(Human &h)
{
    for (unsigned char *c = (unsigned char *)&h; c < (unsigned char *)&h + sizeof(Human); c++)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)*c << " ";

    std::cout << std::endl;
}

void print_raw(Human *h)
{
    for (unsigned char *c = (unsigned char *)h; c < (unsigned char *)h + sizeof(Human); c++)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)*c << " ";

    std::cout << std::endl;
}

int main(int argc, char **argv)
{
    std::cout << sizeof(Human) << std::endl;

    Human h {67, "Kirk"};
    std::cout << "Raw Human: \t";
    print_raw(h);
    
    Man *m = new Man {69, "Sinner"};
    std::cout << "Raw Man: \t";
    print_raw(m);

    delete m;
    
    std::cout << "After delete: \t";
    print_raw(m);
    return 0;
}

