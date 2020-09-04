#include "interface.h"
#include <iostream>
#include <cstdlib>
#include <vector>
#include <string.h>

using namespace std;

/*****************************

BaseInterface

******************************/

BaseInterface::~BaseInterface(){}

void BaseInterface::clear(){
  #if defined _WIN32
  system("cls");
  #elif defined (__LINUX__) || defined(__gnu_linux__) || defined(__linux__)
  system("clear");
  #elif defined (__APPLE__)
  system("clear");
  #endif
}

void BaseInterface::printText(){
  clear();
  cout << m_MenuText << endl;
}

void BaseInterface::updateText(vector<string> user_list){
}

/*****************************

FirstMenu

******************************/

FirstMenu::FirstMenu(vector<string> user_list){
  this->user_list = user_list;
  updateText(user_list);
}

void FirstMenu::updateText(vector<string> user_list){
  this->user_list = user_list;
  m_MenuText = "Users currently online:\n";
  for(int i = 0; i < user_list.size(); i++){
    m_MenuText += to_string(i+1) + ". " + user_list.at(i) + "\n";
  }

  m_MenuText += "Select user to play against: ";
}

BaseInterface* FirstMenu::getNextMenu(string opponent_username, bool& iIsQuitOptionSelected){
  BaseInterface *aNewMenu = 0; // We're setting up the pointer here, but makin sure it's null (0)

  /*if(choice > user_list.size() || choice < 1){
    cout<<"Select identifier from 1 to "<<user_list.size()<<endl;
    return this;
  }*/

  bool isConnected=false;
  for(int i = 0; i < connectedUsers.size(); i++){
    cout<<connectedUsers[i]<<endl;
    if(opponent_username==connectedUsers[i])
      isConnected=true;
  }

  if(!isConnected){
    //cout<<"Invalid input"<<endl;
    m_MenuText+="\n"+opponent_username;
    m_MenuText+=" is an invalid username...select another user: ";

    return this;
  }
  /*challenge request must be sent to the server*/
  //plaintext to encrypt
  uint32_t clear_size = opponent_username.length()+1;
  unsigned char * clear_buf=(unsigned char *)malloc(clear_size);
  clear_buf[0]='2';
  strcpy((char*)&clear_buf[1], opponent_username.c_str());

  ( * client_nonce) ++; //nonce is incremented.
  send_message(sock, toString(* client_nonce,12), clear_buf, clear_size,"server");
  //cout<<"Waiting for "<<opponent_username<<" to accept the request..."<<endl<<endl;
  m_MenuText+="\nWaiting for "+opponent_username+" to accept the request... ";

  //use name instead of identifier because in the meantime a new user may have connected
  //forgeChallengeRequest(user_list.at(choice));

  /*switch (choice) // Notice - I have only done "options". You would obviously need to do this for all of your menus
  {
  case 2:
  {
  aNewMenu = new SecondMenu; // We're creating our new menu object here, and will send it back to the main function below
}

case 3:
{
// Ah, they selected quit! Update the bool we got as input
iIsQuitOptionSelected = true;
}

default:
{
// Do nothing - we won't change the menu
}

}*/

  return this;//aNewMenu; // Sending it back to the main function
}

/*****************************

GameInterface

******************************/


GameInterface::GameInterface(){
  updateGrid();
}

void GameInterface::updateGrid(){

   m_MenuText="\n";
  //cout<<"\U0001F534"<<endl;
  //cout << "\U0001F535"<<endl;

  for(int k = 0; k < ROWS; k++){
    m_MenuText += "\n ";

    for(int i = 0; i < COLUMNS; i++){
      m_MenuText += "\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF ";
    }

    m_MenuText += "\n\uFF5C";

    for(int i = 0; i < COLUMNS; i++){
      m_MenuText += "      " "\uFF5C";
    }

    m_MenuText += "\n\uFF5C";
    for(int i = 0; i < COLUMNS; i++){
      switch(grid[k][i]){
        case empty:
        m_MenuText += "      " "\uFF5C";
        break;
        case red:
        m_MenuText += "  \U0001F534  " "\uFF5C";
        break;
        case blue:
        m_MenuText += "  \U0001F535  " "\uFF5C";
      }
    }

    m_MenuText += "\n\uFF5C";
    for(int i = 0; i < COLUMNS; i++){
      m_MenuText += "      " "\uFF5C";
    }
  }
  m_MenuText += "\n ";

  for(int i = 0; i < COLUMNS; i++){
    m_MenuText += "\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF ";
  }

  m_MenuText += "\n" "    ";
  for(int i = 0; i < COLUMNS; i++){
    m_MenuText += to_string(i+1) + "       ";
  }
  if(!myturn)
      	m_MenuText += "\n\nChoose column where to put the token: ";
  else
	m_MenuText += "\n\nIt's the opponent turn.";

}

BaseInterface* GameInterface::getNextMenu(string colStr, bool& iIsQuitOptionSelected){
  uint32_t col = stoi(colStr);
  //TODO controlli su col
  if(setCell(col, color)){
  	color=(color==red)?blue:red;
  	if(myturn){
	  	//user move must be sent to the opponent
	  	//plaintext to encrypt
	  	  uint32_t clear_size = 2;
		  unsigned char * clear_buf=(unsigned char *)malloc(clear_size);
		  clear_buf[0]='6';

		  clear_buf[1]=colStr[0];
		  ( * session_nonce) ++; //nonce is incremented.
		  send_message(opponent_sock, toString(* session_nonce,12), clear_buf, clear_size,opponent_username);
		  myturn=false;
 	}
  }
  else
  	m_MenuText+="\nInvalid move. Choose a valid column: ";

  return this;
}

//TODO controls for color
bool GameInterface::setCell(int col, cell color){
  col = col - 1;
  //check for out of bound input
  if(col < 0 || col > 6){
  	return false;
	}
  //TODO controls
  for(int i = 5; i >= 0; i--){
    	if(grid[i][col] == empty){
	      grid[i][col] = color;
	      updateGrid();
	      if(checkWinCondition(i, col,color)){
	      		if(myturn==true)
	      			m_MenuText+="\nYOU WON!";
	      		else
	      			m_MenuText+="\nYOU LOST!";
	      		isMatchFinished=true;
	      }
	      return true;
    }
  }
  return false; //column is full
}

bool GameInterface::checkWinCondition(int row, int col,cell color){
  int vertical = 1;//(|)
  int horizontal = 1;//(-)
  int diagonal1 = 1;//(\)
  int diagonal2 = 1;//(/)
  int i;//vertical
  int ii;//horizontal

  //check for vertical(|)
  for(i = row +1;grid[i][col] == color && i <= 5;i++,vertical++);//Check down
  for(i = row -1;grid[i][col] == color && i >= 0;i--,vertical++);//Check up
  if(vertical >= 4)return true;
  //check for horizontal(-)
  for(ii = col -1;grid[row][ii] == color && ii >= 0;ii--,horizontal++);//Check left
  for(ii = col +1;grid[row][ii] == color && ii <= 6;ii++,horizontal++);//Check right
  if(horizontal >= 4) return true;
  //check for diagonal 1 (\)
  for(i = row -1, ii= col -1;grid[i][ii] == color && i>=0 && ii >=0; diagonal1 ++, i --, ii --);//up and left
  for(i = row +1, ii = col+1;grid[i][ii] == color && i<=5 && ii <=6;diagonal1 ++, i ++, ii ++);//down and right
  if(diagonal1 >= 4) return true;
  //check for diagonal 2(/)
  for(i = row -1, ii= col +1;grid[i][ii] == color && i>=0 && ii <= 6; diagonal2 ++, i --, ii ++);//up and right
  for(i = row +1, ii= col -1;grid[i][ii] == color && i<=5 && ii >=0; diagonal2 ++, i ++, ii --);//up and left
  if(diagonal2 >= 4) return true;

  return false;
}

void GameInterface::updateText(vector<string> user_list){
}
