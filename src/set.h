#ifndef SET_H_
#define SET_H_
#include <vector>
#include <map>
#include <string>
#include <algorithm>    // std::copy

namespace Strongvelopens
{
template <typename T>
class Set : public std::vector<T>
{
public:

	Set();
	Set(Set<T> & s);
	Set(const std::vector<T>& array);
	void fromArray(const std::vector<T>& array);
	std::vector<T> toArray();
	bool has(const T& elem) const;
	void add(const T& elem);
	void remove(const T& elem);

	Set<T> join(const Set<T>& s) const;
	Set<T> intersect(const Set<T>& s) const;
	Set<T> subtract(const Set<T>& s) const;
	bool equals(const Set<T>& s) const;
	Set<T>& operator = (const Set<T>& s);

};

template <typename T>
Set<T>::Set()
{
}

template <typename T>
Set<T>::Set(Set<T>& s)
{
	this->fromArray(s.toArray());
}

template <typename T>
Set<T>::Set(const std::vector<T>& array)
{
    this->clear();
    for(int i=0;i<array.size();i++)
    {
        this->add(array[i]);
    }
}

template <typename T>
void Set<T>::fromArray(const std::vector<T>& array)
{
    this->clear();
    for(int i=0;i<array.size();i++)
    {
        this->add(array[i]);
    }
}

template <typename T>
std::vector<T> Set<T>::toArray()
{
    std::vector<T> result;
    result.resize(this->size());
    std::copy ( this->begin(), this->end(), result.begin());
    return result;
}

template <typename T>
bool Set<T>::has(const T& elem) const
{
    return (std::find(this->begin(), this->end(), elem) != this->end());
}

template <typename T>
void Set<T>::add(const T& elem)
{
    if (!this->has(elem))
    {
    	this->push_back(elem);
    }
}

template <typename T>
void Set<T>::remove(const T& elem)
{
    if (this->has(elem))
    {
    	this->erase( std::remove( this->begin(), this->end(), elem ), this->end() );
    }
}

template <typename T>
Set<T> Set<T>::join(const Set& s) const
{
	Set result(*this);
    for(int i=0;i<s.size();i++)
    {
    	result.add(s[i]);
    }
    return result;
}

template <typename T>
Set<T> Set<T>::intersect(const Set& s) const
{
	Set result;
    for(int i=0;i<s.size();i++)
    {
    	if (this->has(s[i]))
    	{
    	    result.add(s[i]);
    	}
    }
    return result;
}

template <typename T>
Set<T> Set<T>::subtract(const Set<T>& s) const
{
	Set result(*this);

    for(int i=0;i<s.size();i++)
    {
        result.remove(s[i]);
    }
    return result;
}

template <typename T>
bool Set<T>::equals(const Set<T>& s) const
{
	if(this->size() != s.size())
	{
		return false;
	}

    if(this->subtract(s).size() > 0 || s.subtract(*this).size() > 0)
    {
        return false;
    }
    return true;
}

template <typename T>
Set<T>& Set<T>::operator = (const Set<T>& s)
{
	this->clear();
    for(int i=0;i<s.size();i++)
    {
    	add(s[i]);
    }
    return *this;
}
}
#endif/* SET_H_ */
